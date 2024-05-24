# Kubernetes 入门指南（三）

> 原文：[`zh.annas-archive.org/md5/1794743BB21D72736FFE64D66DCA9F0E`](https://zh.annas-archive.org/md5/1794743BB21D72736FFE64D66DCA9F0E)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：集群联合

本章将讨论新的联合能力以及如何使用它们来管理跨云提供商的多个集群。我们还将介绍核心结构的联合版本。我们将为您介绍联合部署、副本集、配置映射和事件。

本章将讨论以下主题：

+   联合集群

+   将多个集群联合起来

+   跨多个集群检查和控制资源

+   在多个集群中启动资源

# 介绍联合

尽管 **联合** 在 Kubernetes 中仍然非常新颖，但它为高度追求的跨云提供商解决方案奠定了基础。使用联合，我们可以在本地和一个或多个公共云提供商上运行多个 Kubernetes 集群，并管理利用我们组织的全部资源的应用程序。

这开始为避免云提供商锁定和高可用部署铺平道路，可以将应用服务器放置在多个集群中，并允许与我们的联合集群中位于单个点的其他服务进行通信。我们可以提高对特定提供商或地理位置的中断的隔离性，同时提供更大的灵活性，以便扩展和利用总体基础架构。

目前，联合平面支持这些资源（配置映射、守护程序集、部署、事件、入口、命名空间、副本集、密码和服务）。请注意，联合及其组件处于发布的 Alpha 和 Beta 阶段，因此功能可能仍然有些不稳定。

# 设置联合

尽管我们可以使用我们为其余示例运行的集群，但我强烈建议您从头开始。集群和上下文的默认命名可能对联合系统有问题。请注意，`--cluster-context` 和 `--secret-name` 标志旨在帮助您解决默认命名问题，但对于首次联合，可能仍然会令人困惑且不直接。

因此，本章中我们将从头开始演示示例。可以使用新的、独立的云提供商（AWS 和/或 GCE）帐户，或者拆除当前的集群并通过运行以下命令重置 Kubernetes 控制环境：

```
$ kubectl config unset contexts $ kubectl config unset clusters

```

使用以下命令双重检查是否列出了任何内容：

```
$ kubectl config get-contexts $ kubectl config get-clusters

```

接下来，我们将希望将 `kubefed` 命令放到我们的路径上并使其可执行。导航回您解压 Kubernetes 下载的文件夹。`kubefed` 命令位于 `/kubernetes/client/bin` 文件夹中。运行以下命令进入 bin 文件夹并更改执行权限：

```
$ sudo cp kubernetes/client/bin/kubefed /usr/local/bin
$ sudo chmod +x /usr/local/bin/kubefed

```

# 上下文

**上下文**由 Kubernetes 控制平面用于存储多个集群的身份验证和集群配置。这使我们能够访问和管理从同一个 `kubectl` 访问的多个集群。您可以始终使用我们之前使用过的 `get-contexts` 命令查看可用的上下文。

# 用于联邦的新集群

再次确保你导航到 Kubernetes 下载的位置，并进入`cluster`子文件夹：

```
$ cd kubernetes/cluster/

```

在继续之前，请确保你已经安装、验证和配置了 GCE 命令行和 AWS 命令行。如果你需要在新的环境中执行此操作，请参考第一章，*Kubernetes 简介*。

首先，我们将创建 AWS 集群。请注意，我们正在添加一个名为`OVERRIDE_CONTEXT`的环境变量，它将允许我们将上下文名称设置为符合 DNS 命名标准的内容。DNS 是联邦的关键组件，因为它允许我们进行跨集群发现和服务通信。在联邦世界中，这一点至关重要，因为集群可能位于不同的数据中心甚至提供商中。

运行这些命令来创建你的 AWS 集群：

```
$ export KUBERNETES_PROVIDER=aws
$ export OVERRIDE_CONTEXT=awsk8s
$ ./kube-up.sh

```

接下来，我们将使用`OVERRIDE_CONTEXT`环境变量再次创建一个 GCE 集群：

```
$ export KUBERNETES_PROVIDER=gce
$ export OVERRIDE_CONTEXT=gcek8s
$ ./kube-up.sh

```

如果我们现在看一下我们的上下文，我们会注意到我们刚刚创建的`awsk8s`和`gcek8s`。`gcek8s`前面的星号表示它是`kubectl`当前指向并执行的位置：

```
$ kubectl config get-contexts 

```

上述命令应该产生类似以下的内容：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_09_01.png)

上下文清单

# 初始化联邦控制平面

现在我们有了两个集群，让我们在 GCE 集群中设置联邦控制平面。首先，我们需要确保我们在 GCE 上下文中，然后我们将初始化联邦控制平面：

```
$ kubectl config use-context gcek8s
$ kubefed init master-control --host-cluster-context=gcek8s --dns-zone-name="mydomain.com" 

```

上述命令创建了一个专门用于联邦的新上下文，称为`master-control`。它使用`gcek8s`集群/上下文来托管联邦组件（如 API 服务器和控制器）。它假设 GCE DNS 作为联邦的 DNS 服务。你需要使用你管理的域后缀更新`dns-zone-name`。

默认情况下，DNS 提供商是 GCE。你可以使用`--dns-provider="aws-route53"`将其设置为 AWS `route53`；然而，开箱即用的实现对许多用户仍然存在问题。

如果我们再次检查我们的上下文，我们现在会看到三个上下文：

```
$ kubectl config get-contexts 

```

上述命令应该产生类似以下的内容：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_09_02.png)

上下文清单 #2

在继续之前，让我们确保所有联邦组件都在运行。联邦控制平面使用`federation-system`命名空间。使用指定了命名空间的`kubectl get pods`命令来监视进度。一旦看到两个 API 服务器 pod 和一个控制器 pod，你就应该准备好了：

```
$ kubectl get pods --namespace=federation-system

```

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_09_03-1.png)

联邦 pod 清单 #

现在我们已经设置并运行了联邦组件，让我们切换到该上下文以进行下一步：

```
$ kubectl config use-context master-control

```

# 将集群添加到联邦系统中

现在我们有了联邦控制平面，我们可以将集群添加到联邦系统中。首先，我们将加入 GCE 集群，然后再加入 AWS 集群：

```
$ kubefed join gcek8s --host-cluster-context=gcek8s --secret-name=fed-secret-gce
$ kubefed join awsk8s --host-cluster-context=gcek8s --secret-name=fed-secret-aws

```

# 联邦资源

联邦资源允许我们跨多个集群和/或区域部署。当前，Kubernetes 版本 1.5 支持联合 API 中的一些核心资源类型，包括 ConfigMap、DaemonSets、Deployment、Events、Ingress、Namespaces、ReplicaSets、Secrets 和 Services。

让我们来看一个**联邦部署**，它将允许我们在 AWS 和 GCE 上安排 Pods：

```
apiVersion: extensions/v1beta1
kind: Deployment
metadata:
  name: node-js-deploy
  labels:
    name: node-js-deploy
spec:
  replicas: 3
  template:
    metadata:
      labels:
        name: node-js-deploy
    spec: 
      containers: 
      - name: node-js-deploy 
        image: jonbaier/pod-scaling:latest 
        ports: 
        - containerPort: 80

```

*列表 9-1. *`node-js-deploy-fed.yaml`

使用以下命令创建此部署：

```
$ kubectl create -f node-js-deploy-fed.yaml

```

现在让我们尝试列出此部署中的 Pods：

```
$ kubectl get pods

```

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_09_04.png)

联邦上下文中没有 Pods

我们应该看到类似于上述所示的消息。这是因为我们仍在使用 `master-control` 或联邦上下文，该上下文本身不运行 Pods。然而，我们将在联邦平面上看到部署，并且如果我们检查事件，我们将看到部署实际上是在我们的联合集群上创建的：

```
$ kubectl get deployments
$ kubectl describe deployments node-js-deploy 

```

我们应该看到类似以下的内容。请注意，`Events:` 部分显示了我们在 GCE 和 AWS 上的部署情况：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_09_05-1.png)

联邦 Pods 部署

我们还可以使用以下命令查看联邦事件：

```
$ kubectl get events

```

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_09_06-1.png)

联邦事件

所有三个 Pods 都运行可能需要一段时间。一旦发生这种情况，我们就可以切换到每个集群上下文，并在每个集群上看到一些 Pods。请注意，我们现在可以使用 `get pods`，因为我们在各个集群上而不是在控制平面上：

```
$ kubectl config use-context awsk8s
$ kubectl get pods

```

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_09_07-1.png)

AWS 集群上的 Pods

```
$ kubectl config use-context gcek8s
$ kubectl get pods

```

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_09_08.png)

GCE 集群上的 Pods

我们应该看到三个 Pods 分布在集群中，其中两个在一个集群上，第三个在另一个集群上。Kubernetes 在没有任何手动干预的情况下将其分布在集群中。任何失败的 Pods 将被重新启动，但现在我们增加了两个云提供商的冗余性。

# 联邦配置

在现代软件开发中，将配置变量与应用代码本身分离是很常见的。这样做可以更容易地更新服务 URL、凭据、常见路径等。将这些值放在外部配置文件中意味着我们可以在不重新构建整个应用程序的情况下轻松更新配置。

这种分离解决了最初的问题，但真正的可移植性是当您完全从应用程序中移除依赖关系时实现的。Kubernetes 提供了一个专门用于此目的的配置存储。**ConfigMaps** 是存储键值对的简单结构。

Kubernetes 还支持用于更敏感的配置数据的**Secrets**。这将在第十章 *容器安全性*中更详细地介绍。您可以在单个集群上或在我们此处演示的联邦控制平面上使用该示例，就像我们在这里使用 ConfigMaps 一样。

让我们看一个示例，让我们能够存储一些配置，然后在各种 pod 中使用它。以下清单将适用于联合和单个集群，但我们将继续为此示例使用联合设置。`ConfigMap`种类可以使用文字值、平面文件和目录，最后是 YAML 定义文件创建。以下清单是一个 YAML 定义文件：

```
apiVersion: v1
kind: ConfigMap
metadata:
  name: my-application-config
  namespace: default
data:
  backend-service.url: my-backend-service

```

*Listing 9-2*: `configmap-fed.yaml`

让我们首先切换回我们的联合平面：

```
$ kubectl config use-context master-control

```

现在，使用以下命令创建此清单：

```
$ kubectl create -f configmap-fed.yaml

```

让我们显示我们刚刚创建的`configmap`对象。`-o yaml`标志帮助我们显示完整的信息：

```
$ kubectl get configmap my-application-config -o yaml

```

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_09_09.png)

联合`ConfigMap`描述

现在我们有了一个`ConfigMap`对象，让我们启动一个可以使用`ConfigMap`的联合`ReplicaSet`。这将在我们的集群中创建可以访问`ConfigMap`对象的 pod 的副本。`ConfigMap`可以通过环境变量或挂载卷进行访问。这个示例将使用一个提供文件夹层次结构和每个键内容表示值的挂载卷：

```
apiVersion: extensions/v1beta1
kind: ReplicaSet
metadata:
  name: node-js-rs
spec:
  replicas: 3
  selector:
    matchLabels:
      name: node-js-configmap-rs
  template:
    metadata:
      labels:
        name: node-js-configmap-rs
    spec:
      containers:
      - name: configmap-pod
        image: jonbaier/node-express-info:latest
        ports:
        - containerPort: 80
          name: web
        volumeMounts:
        - name: configmap-volume
          mountPath: /etc/config
      volumes:
      - name: configmap-volume
        configMap:
          name: my-application-config

```

*Listing 9-3*: `configmap-rs-fed.yaml`

使用`kubectl create -f configmap-rs-fed.yaml`创建此 pod。创建后，我们将需要切换上下文到其中一个运行 pod 的集群。您可以随意选择，但我们将在这里使用 GCE 上下文：

```
$ kubectl config use-context gcek8s

```

现在我们专门在 GCE 集群上，让我们检查这里的`configmaps`：

```
$ kubectl get configmaps

```

如您所见，`ConfigMap`本地传播到每个集群。接下来，让我们从我们的联合`ReplicaSet`中找到一个 pod：

```
$ kubectl get pods

```

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_09_10.png)

GCE 集群上的 Pods

让我们从清单中选取一个`node-js-rs` pod 名称，并使用`kubectl exec`运行一个 bash shell：

```
$ kubectl exec -it node-js-rs-6g7nj bash

```

然后更改目录到我们在 pod 定义中设置的`/etc/config`文件夹。列出这个目录会显示一个名为我们之前定义的`ConfigMap`的单个文件：

```
$ cd /etc/config
$ ls

```

如果我们然后用以下命令显示文件的内容，我们应该看到我们之前输入的值：`my-backend-service`：

```
$ echo $(cat backend-service.url)

```

如果我们查看联合集群中任何一个 pod，我们将看到相同的值。这是一种很好的方式，可以将配置从应用程序中解耦并分布到我们的集群中。

# 其他联合资源

到目前为止，我们看到了联合部署、ReplicaSets、事件和 ConfigMaps 在行动中。`DaemonSets`、`Ingress`、`Namespaces`、`Secrets`和`Services`也受到支持。您的具体设置将有所不同，您可能会有一组与我们此处示例不同的集群。如前所述，这些资源仍处于测试阶段，因此值得花些时间尝试各种资源类型，并了解联合构造对您的特定基础设施组合的支持情况。

# 真正的多云

这是一个值得关注的激动人心的领域。随着它的发展，我们有一个真正良好的开始来进行多云实现，并在地区、数据中心甚至云提供商之间提供冗余。

虽然 Kubernetes 提供了一条简便且令人兴奋的多云基础设施路径，但重要的是要注意，生产多云需要比分布式部署更多的东西。从日志记录和监控到合规性和主机加固的全套功能，在多提供商设置中有很多要管理的内容。

真正的多云采用将需要一个精心规划的架构，而 Kubernetes 在追求这一目标上迈出了一大步。

# 摘要

在本章中，我们介绍了 Kubernetes 中的新联邦能力。我们看到了如何将集群部署到多个云提供商，并从单个控制平面管理它们。我们还在 AWS 和 GCE 中的集群中部署了一个应用程序。虽然这些功能是新的，仍主要处于 alpha 和 beta 阶段，但我们现在应该有能力利用它们，并将其作为标准 Kubernetes 运行模型的一部分。

在下一章中，我们将深入探讨另一个高级话题，安全性。我们将介绍安全容器的基础知识，以及如何保护您的 Kubernetes 集群。我们还将研究 Secrets 结构，它使我们能够存储类似于我们之前的 `ConfigMap` 示例中的敏感配置数据。


# 第十章：容器安全

本章将从容器运行时级别到主机本身讨论容器安全的基础知识。我们将讨论如何将这些概念应用于在 Kubernetes 集群中运行的工作负载，并讨论一些与运行您的 Kubernetes 集群特定相关的安全关注点和实践。

本章将讨论以下主题：

+   基本容器安全

+   容器镜像安全和持续性漏洞扫描

+   Kubernetes 集群安全

+   Kubernetes 秘密

# 容器安全基础

容器安全是一个深入的主题领域，本身就可以填满一本书。话虽如此，我们将涵盖一些高级别的关注点，并为思考这一领域提供一个起点。

在 第一章* Kubernetes 介绍 * 的 * 容器简介 * 部分，我们看到了 Linux 内核中支持容器技术的一些核心隔离特性。理解容器工作原理的细节是理解管理它们中的各种安全问题的关键。

深入研究的好文章是 *NCC 的白皮书*，*理解和加固 Linux 容器*（您可以在本章末尾的*参考文献*部分的第 1 点中查看更多详细信息）。在 *第七部分* 中，该论文探讨了容器部署中涉及的各种攻击向量，我将总结（您可以在本章末尾的*参考文献*部分的第 1 点中查看更多详细信息）。

# 保持容器受限

论文中讨论的最明显的特征之一是逃避容器结构的孤立/虚拟化。现代容器实现使用命名空间来隔离进程，并允许控制容器可用的 Linux 权限。此外，越来越多地采用安全的默认配置来配置容器环境。例如，默认情况下，Docker 仅启用了一小部分权限（您可以在本章末尾的*参考文献*部分的第 2 点中查看更多详细信息）。网络是另一个逃逸的途径，由于现代容器设置中插入了各种网络选项，这可能是具有挑战性的。

论文中讨论的下一个领域是两个容器之间的攻击。*用户*命名空间模型在这里为我们提供了额外的保护，通过将容器内的 root 用户映射到主机上的较低级别用户。网络当然仍然是一个问题，需要在选择和实施容器网络解决方案时进行适当的勤勉和关注。

容器内部的攻击是另一个向量，与之前的担忧一样，命名空间和网络对于保护至关重要。在这种情况下至关重要的另一个方面是应用程序本身的安全性。代码仍然需要遵循安全编码实践，并且软件应该定期更新和打补丁。最后，容器镜像的效率具有缩小攻击面的附加好处。镜像应该只包含必需的软件包和软件。

# 资源耗尽和编排安全性

与拒绝服务攻击类似，在计算的各个其他领域中，资源耗尽在容器世界中非常相关。虽然 cgroups 对 CPU、内存和磁盘使用等资源使用提供了一些限制，但仍然存在有效的资源耗尽攻击途径。诸如 Docker 等工具为 cgroups 的限制提供了一些起始默认值，Kubernetes 还提供了可以放置在集群中运行的容器组的额外限制。了解这些默认值并为您的部署进行调整至关重要。

尽管 Linux 内核和启用容器的功能给我们提供了一定形式的隔离，但它们对于 Linux 操作系统来说还是相当新的。因此，它们仍然包含自己的错误和漏洞。用于能力和命名空间的内置机制可能会存在问题，跟踪这些问题作为安全容器操作的一部分是很重要的。

NCC 论文涵盖的最后一个领域是容器管理层本身的攻击。Docker 引擎、镜像仓库和编排工具都是重要的攻击向量，应在制定策略时予以考虑。我们将在接下来的章节更深入地研究如何解决镜像仓库和作为编排层的 Kubernetes。

如果你对 Docker 实现的特定安全功能感兴趣，请查看这里：

[`docs.docker.com/engine/security/security/`](https://docs.docker.com/engine/security/security/).

# 镜像仓库

漏洞管理是现代 IT 运营的关键组成部分。零日漏洞正在增加，即使是有补丁的漏洞也可能很难修复。首先，应用程序所有者必须了解其漏洞和潜在补丁。然后，这些补丁必须集成到系统和代码中，通常需要额外的部署或维护窗口。即使对漏洞有所了解，修复也经常有延迟，通常需要大型组织数月时间才能打补丁。

虽然容器极大地改进了更新应用程序和最小化停机时间的过程，但漏洞管理中仍然存在挑战。特别是因为攻击者只需暴露一个这样的漏洞；任何少于 100% 的系统都未打补丁都存在被攻击的风险。

需要的是更快的反馈循环来解决漏洞。持续扫描并与软件部署生命周期结合是加速漏洞信息和修复的关键。幸运的是，这正是最新容器管理和安全工具正在构建的方法。

# 持续漏洞扫描

在这个领域出现了一个开源项目 **Clair**。我们从 *Clair* GitHub 页面了解到：<q>Clair 是一个用于对 [appc](https://github.com/appc/spec) 和 [docker](https://github.com/docker/docker/blob/master/image/spec/v1.md) 容器进行静态分析漏洞的开源项目</q>。

您可以在以下链接访问 Clair：

[`github.com/coreos/clair`](https://github.com/coreos/clair)。

Clair 会针对 **公共漏洞和利用** (**CVEs**) 扫描您的代码。它可以集成到您的 CI/CD 流水线中，并在新构建的响应中运行。如果发现漏洞，它们可以作为反馈进入流水线，甚至停止部署并失败构建。这迫使开发人员在其正常发布过程中意识到并纠正漏洞。

Clair 可以与多个容器镜像仓库和 CI/CD 流水线集成。

Clair 甚至可以部署在 Kubernetes 上：[`github.com/coreos/clair#kubernetes`](https://github.com/coreos/clair#kubernetes)。

Clair 也被用作 CoreOS 的 Quay 镜像仓库中的扫描机制。Quay 提供了许多企业功能，包括持续漏洞扫

[`quay.io/`](https://quay.io/)

Docker Hub 和 Docker Cloud 都支持安全扫描。再次强调，推送到仓库的容器会自动针对 CVE 进行扫描，并根据任何发现发送漏洞通知。此外，还会对代码进行二进制分析，以与已知版本的组件签名进行匹配。

还有一系列其他的扫描工具可用于扫描您的镜像仓库，包括 **OpenSCAP** 以及 **Twistlock** 和 **AquaSec**，我们将在第十二章，*走向生产就绪*中介绍。

# 镜像签名和验证

无论您是在内部使用私有镜像仓库还是在 Docker Hub 等公共仓库上使用，重要的是要知道您正在运行的只是您的开发人员编写的代码。下载时恶意代码或中间人攻击的潜在可能性是保护容器镜像的重要因素。

因此，rkt 和 Docker 都支持签署映像并验证内容未更改的能力。发布者可以在将映像推送到存储库时使用密钥签署映像，用户可以在客户端下载并验证签名后使用：

来自 rkt 文档：

<q>"在执行远程获取的 ACI 之前，rkt 将根据 ACI 创建者生成的附加签名对其进行验证。"</q>

+   [`coreos.com/rkt/docs/latest/subcommands/trust.html`](https://coreos.com/rkt/docs/latest/subcommands/trust.html)

+   [`coreos.com/rkt/docs/latest/signing-and-verification-guide.html`](https://coreos.com/rkt/docs/latest/signing-and-verification-guide.html) 来自 Docker 文档：

    <q>"内容信任使您能够验证从注册表收到的所有数据的完整性和发布者，无论通过哪个渠道。"</q> [`docs.docker.com/engine/security/trust/content_trust/`](https://docs.docker.com/engine/security/trust/content_trust/) 来自 Docker Notary GitHub 页面：

    <q>"Notary 项目包括用于运行和与受信任的集合交互的服务器和客户端。"</q> [`github.com/docker/notary`](https://github.com/docker/notary)

# Kubernetes 集群安全

Kubernetes 在其最新版本中持续添加了许多安全功能，并且具有一套完整的控制点，可用于您的集群；从安全的节点通信到 Pod 安全，甚至是敏感配置数据的存储。

# 安全的 API 调用

在每次 API 调用期间，Kubernetes 都会应用一些安全控制。此安全生命周期在此处描述：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_10_01.png)

API 调用生命周期

在建立安全 TLS 通信之后，API 服务器通过**授权**和**身份验证**。最后，在请求到达 API 服务器之前，会应用一个**准入控制器**循环。

# 安全的节点通信

Kubernetes 支持在 API 服务器和任何客户端之间包括节点本身之间建立安全通信渠道。无论是 GUI 还是`kubectl`等命令行实用程序，我们都可以使用证书与 API 服务器进行通信。因此，API 服务器是对集群进行任何更改的中心交互点，是一个关键组件以确保安全。

在诸如 GCE 之类的部署中，默认情况下在每个节点上部署了`kubelet`以进行安全通信。此设置使用 TLS 引导启动和新证书 API 与 API 服务器建立安全连接，使用 TLS 客户端证书和**证书颁发机构**（**CA**）集群。

# 授权和身份验证插件

Kubernetes 中用于身份验证和授权的插件机制还处于初期阶段。但是，这些功能在接下来的几个版本中也在继续开发。还有第三方提供者与这里的功能集成。

目前支持身份验证的形式包括令牌、密码和证书，并计划在以后的阶段添加插件功能。支持 OpenID Connect 令牌，还有几个第三方实现，如来自 CoreOS 的 Dex 和来自 Cloud Foundry 的 aser 账户和身份验证。

授权已经支持了三种模式。完整的**RBAC**（即**基于角色的访问控制**）模式仍在进行中，最终将从 Kubernetes 本身引入成熟的基于角色的身份验证。**基于属性的访问控制**（**ABAC**）已经得到支持，并允许用户通过文件中的属性定义权限。最后，支持 webhook 机制，允许通过 REST Web 服务调用与第三方授权进行集成。

请在这里了解更多关于每个领域的信息：

+   [`kubernetes.io/docs/admin/authorization/`](http://kubernetes.io/docs/admin/authorization/)

+   [`kubernetes.io/docs/admin/authentication/`](http://kubernetes.io/docs/admin/authentication/)

# 准入控制器

Kubernetes 还提供了一种与附加验证集成的机制作为最后一步。这可以是图像扫描、签名检查或任何能够以指定方式响应的东西。当进行 API 调用时，会调用该钩子，服务器可以运行其验证。准入控制器还可用于转换请求并添加或更改原始请求。操作运行后，然后发送带有指示 Kubernetes 允许或拒绝调用的状态的响应。

这对于验证或测试图像尤其有帮助，正如我们在上一节中提到的那样。`ImagePolicyWebhook`插件提供了一个准入控制器，允许与额外的图像检查集成。

欲了解更多信息，请访问以下文档中的“使用准入控制器”页面：

[`kubernetes.io/docs/admin/admission-controllers/`](https://kubernetes.io/docs/admin/admission-controllers/).

# Pod 安全策略和上下文

Kubernetes 安全工具箱中的最新添加之一是**Pod 安全策略和上下文**。这允许用户控制容器进程和附加卷的用户和组，限制使用主机网络或命名空间，甚至将根文件系统设置为只读。此外，我们可以限制可用的功能，并为应用于每个 pod 中的容器的标签设置 SELinux 选项。

除了 SELinux 外，Kubernetes 还通过注释添加了对使用 AppArmor 的支持。有关更多信息，请参阅以下文档页面：

[`kubernetes.io/docs/admin/apparmor/`](https://kubernetes.io/docs/admin/apparmor/).

我们将通过一个示例演示如何使用 pod 安全上下文为我们的 pod 添加一些约束。由于功能仍处于 beta 阶段，我们需要启用 beta 扩展 API，并在使用的准入控制器列表中添加`PodSecurityPolicy`。

# 启用 beta API

首先，您需要 SSH 到您的主节点，切换到**root**用户，然后使用您首选的编辑器编辑`/etc/kubernetes/manifests/kube-apiserver.manifest`文件。同样，我们可以通过 Google Cloud CLI 进行 SSH，或者使用 Google Cloud Console，在 VM 实例页面上有一个内置的 SSH 客户端。

最佳实践是不要直接 SSH 到节点本身。然而，在本书的几个地方，我们已经这样做了，用于说明目的。重要的是要了解节点本身运行的情况，并且有时候对于学习和故障排除可能是必要的。话虽如此，当您只需要在集群或 pod 中运行命令时，请使用诸如`kubectl exec`之类的工具。

滚动到命令部分，我们应该看到类似以下清单的内容：

```
"bin/sh",
"-c",
"/usr/local/bin/kube-apiserver --v=2 --cloud-config=/etc/gce.conf --address=127.0.0.1 --allow-
privileged=true --authorization-policy-file=/etc/srv/kubernetes/abac-authz-policy.jsonl --basic-auth-file=/etc/srv/kubernetes/basic_auth.csv --cloud-provider=gce --client-ca-file=/etc/srv/kubernetes/ca.crt 
--etcd-servers=http://127.0.0.1:2379 --etcd-servers-overrides=/events#http://127.0.0.1:4002 --secure-port=443 --tls-cert-file=/etc
/srv/kubernetes/server.cert --tls-private-key-file=/etc/srv/kubernetes/server.key --token-auth-file=/etc/srv/kubernetes/known_tokens.csv --storage-backend=etcd2 --target-ram-mb=180 --service-cluster-ip-range=10.0.0.0/16 --etcd-quorum-read=false --admission-control=NamespaceLifecycle,LimitRanger,ServiceAccount,PersistentVolumeLabel,DefaultStorageClass,ResourceQuota 
--authorization-mode=ABAC --allow-privileged=true 1>>/var/log/kube-apiserver.log 2>&1"

```

你的清单可能会有所不同，所以只需按照下面粗体标记的参数添加。同时，复制原始清单作为备份，以便以后需要时可以恢复：

```
"bin/sh",
"-c",
"/usr/local/bin/kube-apiserver --v=2 --cloud-config=/etc/gce.conf --address=127.0.0.1 
--allow-privileged=true --authorization-policy-file=/etc/srv/kubernetes/abac-authz-policy.jsonl --basic-auth-file=/etc/srv/kubernetes/basic_auth.csv --cloud-provider=gce --client-ca-file=/etc/srv/kubernetes/ca.crt --etcd-servers=http://127.0.0.1:2379 --etcd-servers-overrides=/events#http://127.0.0.1:4002 --secure-port=443 --tls-cert-file=/etc/srv/kubernetes/server.cert --tls-private-key-file=/etc/srv/kubernetes/server.key --token-auth-file=/etc/srv/kubernetes/known_tokens.csv --storage-backend=etcd2 --target-ram-mb=180 --service-cluster-ip-range=10.0.0.0/16 --etcd-quorum-read=false 
--admission-control=NamespaceLifecycle,LimitRanger,ServiceAccount,PersistentVolumeLabel,DefaultStorageClass,ResourceQuota,PodSecurityPolicy --authorization-mode=ABAC --allow-privileged=true --runtime-config=extensions/v1beta1=true,extensions/v1beta1/podsecuritypolicy=true 1>>/var/log/kube-apiserver.log 2>&1"

```

如果你拥有 root shell，保存文件并退出`sudo`。如果一切顺利，Kubernetes 应该注意到清单的更改并重新启动 API 服务器。这可能需要几分钟，在重启期间，`kubectl`可能会失去响应。我通常使用以下命令来观察：

```
$ kubectl get pods --namespace=kube-system

```

观察`STATUS`和`AGE`列。一旦重启成功，我们将有一个`Running`的`STATUS`和一个几分钟或更短的`AGE`。

如果我们在清单中有任何拼写错误，我们可能会在`STATUS`中看到错误，甚至会获得一个永久性无响应的`kubectl`。如果发生这种情况，我们将需要恢复我们之前的参数。如果一切都失败了，您可以重新启动实例。GCE 设置的默认值有一个引导脚本，该脚本将使用默认设置替换清单。

一旦您的 API 服务器更新并运行，我们就可以添加一个安全策略，并运行一个定义了 pod 安全上下文的 pod。该策略在集群级别运行，并强制执行所有 pod 的策略。pod 安全上下文设置在 pod 定义中，并且仅适用于该 pod。

# 创建 PodSecurityPolicy

现在我们已经添加了`PodSecurityPolicy`准入控制器，我们需要在*列表 10-2*下面进一步创建一个示例之前添加一个 pod 安全策略。如果我们现在尝试创建该 pod，我们将看到类似于这样的错误：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_10_02.png)

没有 PodSecurityPolicy 的 Pod 错误

再次强调，pod 安全策略适用于整个集群：

```
{
  "kind": "PodSecurityPolicy",
  "apiVersion":"extensions/v1beta1",
  "metadata": {
    "name": "default"
  },
  "spec": {
    "privileged": false,
    "seLinux": {
      "rule": "RunAsAny"
    },
    "supplementalGroups": {
      "rule": "RunAsAny"
    },
    "runAsUser": {
      "rule": "RunAsAny"
    },
    "fsGroup": {
      "rule": "RunAsAny"
    },
    "volumes": ["*"],
    "readOnlyRootFilesystem": true
  }
}

```

*列表 10-1*：`default-security-policy.json`

使用以下命令创建：

```
$ kubectl create -f default-security-policy.json

```

上述默认策略不允许容器以特权模式运行。它允许任何 seLinux 标签，任何附加的组 ID，任何用户运行第一个进程，以及任何文件系统的组 ID。它还支持所有类型的卷。

您可以在源代码中找到所有可能的参数，但为方便起见，我创建了以下表格。您可以在我的新网站上找到更多类似这样的便捷查找：

[`www.kubesheets.com`](https://www.kubesheets.com)

| **参数** | **类型** | **描述** | **必需** |
| --- | --- | --- | --- |
| `Privileged` | `bool` | 允许或禁止以特权运行 Pod。 | 否 |
| `DefaultAddCapabilities` | `[]v1.Capaility` | 这定义了添加到容器中的一组默认功能。如果 Pod 指定了一个要删除的功能，那么将覆盖然后添加到这里。值是 POSIX 功能的字符串，减去前缀`CAP_`。例如，`CAP_SETUID` 将是 `SETUID`。[`man7.org/linux/man-pages/man7/capabilities.7.html`](http://man7.org/linux/man-pages/man7/capabilities.7.html) | 否 |
| `RequiredDropCapabilities` | `[]v1.Capaility` | 这定义了必须从容器中丢弃的一组功能。Pod 不能指定这些功能中的任何一个。值是 POSIX 功能的字符串，减去前缀`CAP_`。例如，`CAP_SETUID` 将是 `SETUID`。[`man7.org/linux/man-pages/man7/capabilities.7.html`](http://man7.org/linux/man-pages/man7/capabilities.7.html) | 否 |
| `AllowedCapabilities` | `[]v1.Capaility` | 这定义了一组允许并可以添加到容器中的功能。Pod 可以指定这些功能中的任何一个。值是 POSIX 功能的字符串，减去前缀`CAP_`。例如，`CAP_SETUID` 将是 `SETUID`。[`man7.org/linux/man-pages/man7/capabilities.7.html`](http://man7.org/linux/man-pages/man7/capabilities.7.html) | 否 |
| `Volumes` | `[]FSType` | 此列表定义可以使用的卷。留空以使用所有类型。[`github.com/kubernetes/kubernetes/blob/release-1.5/pkg/apis/extensions/v1beta1/types.go#L1127`](https://github.com/kubernetes/kubernetes/blob/release-1.5/pkg/apis/extensions/v1beta1/types.go#L1127) | 否 |
| `HostNetwork` | `bool` | 允许或禁止 Pod 使用主机网络。 | 否 |
| `HostPorts` | `[]HostPortRange` | 这让我们能够限制可以暴露的可允许主机端口。 | 否 |
| `HostPID` | `bool` | 允许或禁止 Pod 使用主机 PID。 | 否 |
| `HostIPC` | `bool` | 允许或禁止 Pod 使用主机 IPC。 | 否 |
| `SELinux` | `SELinuxStrategyOptions` | 将其设置为这里定义的策略选项之一：[`kubernetes.io/docs/user-guide/pod-security-policy/#strategies`](https://kubernetes.io/docs/user-guide/pod-security-policy/#strategies) | 是 |
| `RunAsUser` | `RunAsUserStrategyOptions` | 将其设置为以下策略选项之一，如此处所定义：[`kubernetes.io/docs/user-guide/pod-security-policy/#strategies`](https://kubernetes.io/docs/user-guide/pod-security-policy/#strategies) | 是 |
| `SupplementalGroups` | `SupplementalGroupsStrategyOptions` | 将其设置为以下策略选项之一，如此处所定义：[`kubernetes.io/docs/user-guide/pod-security-policy/#strategies`](https://kubernetes.io/docs/user-guide/pod-security-policy/#strategies) | 是 |
| `FSGroup` | `FSGroupStrategyOptions` | 将其设置为以下策略选项之一，如此处所定义：[`kubernetes.io/docs/user-guide/pod-security-policy/#strategies`](https://kubernetes.io/docs/user-guide/pod-security-policy/#strategies) | 是 |
| `ReadOnlyRootFilesystem` | `bool` | 将其设置为 `true` 将会拒绝该 pod 或强制其以只读根文件系统运行。 | 否 |

*表 10-1\. Pod 安全策略参数*（你可以在本章末尾的参考文献第 3 点中查看更多详细信息）

现在我们对集群有了一个基本策略，让我们创建一个 `Pod`。首先，我们将创建一个带有我们的 `node-express-info` 容器的 `Pod`：

```
apiVersion: v1
kind: Pod
metadata:
    name: node-js-nopsc
spec:
  containers:
  - name: node-js-nopsc
    image: jonbaier/node-express-info:latest
    ports:
    - containerPort: 80

```

*清单 10-2*: `nodejs-pod-nopsc.yaml`

使用上述清单创建 pod。然后使用 `kubectl exec` 命令获取 pod 内部的 shell。接下来，我们将尝试使用 `touch` 命令创建一个文件：

```
$ kubectl exec -it node-js-nopsc bash root@node-js-nopsc:/src# touch file.txt

```

我们应该会收到类似于 `touch: cannot touch 'file.txt': Read-only file system` 的错误。这是因为我们将 `ReadOnlyFileSystem` 属性设置为 true，所以所有容器（无论是否定义了 pod 安全上下文）现在都以只读根文件系统运行。键入 `exit` 退出此 pod。

# 使用 PodSecurityContext 创建一个 pod

现在我们已经看到了 pod 安全策略的影响，让我们来探索一下 pod 安全上下文。在这里，我们可以定义 `seLinuxOptions`，它让我们能够为 pod 中的容器定义标签上下文。我们还可以定义 `runAsUser`，以指定每个容器将使用的 UID，以及 `runAsNonRoot` 标志，它将简单地阻止以 `UID 0` 或 `root` 运行的容器启动。我们还可以使用 `supplementalGroup` 指定每个容器中第一个进程的组（GID）。最后，我们可以使用 `fsGroup` 指定文件系统所有权和新文件的组（GID）。

*清单 10-4* 是我们先前的 `node-express-info` pod 的一个版本，其中 `runAsNonRoot` 设置为 `true`。重要的是要理解，如果在 `Dockerfile` 中没有定义用户，则 root（`UID 0`）是默认用户。 *清单 10-3* 显示了我们 `node-express-info` 容器的 `Dockerfile`。我们没有定义 `USER` 指令，因此它将以 root 身份运行：

```
FROM node:latest

ADD src/ /src
WORKDIR /src

RUN npm install

ENV PORT=80

CMD ["node", "index.js"]

```

*清单 10-3*: `node-express-info Dockerfile`

```
apiVersion: v1
kind: Pod
metadata:
    name: node-js-pod
spec:
  containers:
  - name: node-js-pod
    image: jonbaier/node-express-info:latest
    ports:
    - containerPort: 80
  securityContext:
    runAsNonRoot: true

```

*清单 10-4*: `nodejs-pod-psc.yaml`

理解安全上下文与容器构建方式之间的关系很重要。如果我们尝试使用 `kubectl create -f nodejs-pod-psc.yaml` 创建上述的 *Listing 10-4*，我们会发现它永远不会启动，并给出 `验证非根错误`：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_10_03.png)

验证非根错误

理解以安全方式运行容器不仅仅是管理员添加约束的任务。这项工作必须与将正确创建图像的开发人员合作进行。

# 清理工作

我们制定的策略可能对学习和开发来说过于严格，因此您可能希望删除它。您可以使用以下命令执行此操作：

```
$ kubectl delete psp default 

```

您还需要撤消在本节开头对 Kubernetes 主节点上的 `/etc/kubernetes/manifests/kube-apiserver.manifest` 所做的更改。具体来说，您应该从 `admission-control` 部分的列表中删除 `PodSecurityPolicy`。

# 额外的考虑事项

除了我们刚刚审查的功能之外，Kubernetes 还有许多其他构造应该在整个集群强化过程中考虑。在本书的前面，我们看到了为多租户提供逻辑分离的命名空间。虽然命名空间本身不会隔离实际的网络流量，但一些网络插件，如 Calico 和 Canal，提供了额外的网络策略功能。我们还看到了可以为每个命名空间设置的配额和限制，应该用于防止单个租户或项目在集群中消耗过多的资源。

# 保护敏感应用程序数据（秘密）

有时，我们的应用程序需要保存敏感信息。这可以是登录到数据库或服务的凭据或令牌。将这些敏感信息存储在图像本身中是应该避免的。在这里，Kubernetes 在秘密构造中为我们提供了一个解决方案。

**秘密**给了我们一种在资源定义文件中不包含明文版本的敏感信息的存储方式。秘密可以挂载到需要它们的 pod 中，然后在 pod 内部以包含秘密值的文件形式访问。或者，你也可以通过环境变量暴露秘密。

我们可以轻松地使用 YAML 或命令行创建秘密。秘密确实需要进行 base64 编码，但如果我们使用 `kubectl` 命令行，则此编码将为我们执行。

让我们从以下秘密开始：

```
$ kubectl create secret generic secret-phrases --from-literal=quiet-phrase="Shh! Dont' tell"

```

然后我们可以使用以下命令检查秘密：

```
$ kubectl get secrets

```

现在我们已经成功创建了秘密，让我们创建一个可以使用秘密的 pod。通过附加卷的方式，秘密在 pod 中被消耗。在下面的 *Listing 10-5* 中，您会注意到我们使用 `volumeMount` 将秘密挂载到容器中的一个文件夹：

```
apiVersion: v1
kind: Pod
metadata:
  name: secret-pod
spec:
  containers:
  - name: secret-pod
    image: jonbaier/node-express-info:latest
    ports:
    - containerPort: 80
      name: web
    volumeMounts:
      - name: secret-volume
        mountPath: /etc/secret-phrases
  volumes:
  - name: secret-volume
    secret:
      secretName: secret-phrases

```

*Listing 10-5*：`secret-pod.yaml`

使用`kubectl create -f secret-pod.yaml`命令创建此 Pod。一旦创建，我们可以通过`kubectl exec`获取该 Pod 中的 bash shell，然后切换到我们在 Pod 定义中设置的`/etc/secret-phrases`文件夹。列出该目录会显示一个单独的文件，文件名为我们之前创建的秘密：

```
$ kubectl exec -it secret-pod bash
$ cd /etc/secret-phrases
$ ls

```

如果我们显示这些内容，应该会看到我们之前编码的短语`Shh! Dont' tell`：

```
$ cat quiet-phrase

```

通常，这将用于数据库或服务的用户名和密码，或任何敏感凭据和配置数据。

请注意，Secrets 仍处于早期阶段，但它们是生产操作的重要组成部分。这里计划对未来发布进行一些改进。目前，Secrets 仍以明文形式存储在 etcd 服务器中。但是，Secrets 构建确实允许我们控制哪些 Pod 可以访问它，并将信息存储在 tmpfs 上，但不会为每个 Pod 持续存储它。您可能希望对生产就绪系统采取更多保护措施。

# 摘要

我们研究了基本容器安全性和一些重要的考虑因素。我们还涉及了基本镜像安全性和持续漏洞扫描。在本章稍后，我们将查看 Kubernetes 的整体安全功能，包括用于存储敏感配置数据的 Secrets，安全的 API 调用，甚至为在我们集群上运行的容器设置安全策略和上下文。

现在，您应该已经有了一个稳固的起点，用于保护您的集群并向生产环境迈进。为此，下一章将涵盖向生产环境迈进的整体策略，并且还将查看一些第三方供应商提供的填补空白并在路上协助您的工具。

# 参考资料

1.  [`www.nccgroup.trust/globalassets/our-research/us/whitepapers/2016/april/ncc_group_understanding_hardening_linux_containers-10pdf/`](https://www.nccgroup.trust/us/our-research/understanding-and-hardening-linux-containers/)

1.  [`github.com/docker/docker/blob/master/oci/defaults_linux.go#L62-L77`](https://github.com/docker/docker/blob/master/oci/defaults_linux.go#L62-L77)

1.  [`github.com/kubernetes/kubernetes/blob/release-1.5/pkg/apis/extensions/v1beta1/types.go#L1075`](https://github.com/kubernetes/kubernetes/blob/release-1.5/pkg/apis/extensions/v1beta1/types.go#L1075)


# 第十一章：使用 OCP、CoreOS 和 Tectonic 扩展 Kubernetes

本章的前半部分将介绍开放标准如何鼓励多样化的容器实现生态系统。我们将查看**开放容器倡议**（**OCI**）及其提供开放容器规范的使命。本章的后半部分将介绍 CoreOS 及其作为主机操作系统的优势，包括性能和对各种容器实现的支持。此外，我们还将简要介绍 CoreOS 提供的 Tectonic 企业版。

本章将讨论以下主题：

+   为什么标准很重要？

+   开放容器倡议和云原生计算基金会

+   容器规范与实现

+   CoreOS 及其优势

+   Tectonic

# 标准的重要性

过去两年来，容器化技术的普及度有了巨大的增长。尽管 Docker 一直处于这一生态系统的中心位置，但容器领域的参与者数量正在增加。目前已经有许多替代方案用于容器化和 Docker 实现本身（**rkt**、**Garden** 等）。此外，还有丰富的第三方工具生态系统，可以增强和补充您的容器基础设施。Kubernetes 明确地位于该生态系统的编排方面，但底线是所有这些工具都构成了构建云原生应用程序的基础。

正如我们在书的开头提到的，容器最吸引人的一个特点是它们能够将我们的应用程序打包部署到各种环境层（即开发、测试和生产）和各种基础设施提供商（如 GCP、AWS、本地部署等）。

要真正支持这种部署灵活性，我们不仅需要容器本身具有共同的平台，还需要底层规范遵循一套共同的基本规则。这将允许实现既灵活又高度专业化。例如，一些工作负载可能需要在高度安全的实现上运行。为了提供这一点，实现将不得不对一些实现的方面做出更多有意识的决定。无论哪种情况，如果我们的容器建立在所有实现都同意并支持的共同结构上，我们将拥有更多的灵活性和自由度。

# 开放容器倡议

首个获得广泛行业参与的倡议之一是 OCI。在 36 家行业合作伙伴中包括 Docker、Red Hat、VMware、IBM、Google 和 AWS，在 OCI 网站上列出了它们的名单：

[`www.opencontainers.org/`](https://www.opencontainers.org/)。

OCI 的目的是将实现（如 Docker 和 rkt）与容器化工作负载的格式和运行时的标准规范分开。根据它们自己的术语，OCI 规范的目标有三个基本原则（你可以在本章末尾的*参考资料*部分的第 1 点中找到更多详细信息）：

+   创建容器镜像格式和运行时的正式规范，这将使符合规范的容器可以在所有主要的、符合规范的操作系统和平台上可移植，而不会受到人为的技术障碍的限制。

+   接受、维护和推进与这些标准相关的项目（**项目**）。它将寻求达成一致的一组容器操作（启动、执行、暂停等）以及与容器运行时相关的运行时环境的标准。

+   将之前提到的标准与其他提议的标准进行协调，包括 appc 规范。

# 云原生计算基金会

另一个也被广泛接受的倡议是**云原生计算基金会**（**CNCF**）。虽然仍然专注于容器化工作负载，但 CNCF 在堆栈中的应用设计层次上运作得更高。其目的是提供一套标准的工具和技术，用于构建、运行和编排云原生应用堆栈。云计算使我们可以访问各种新技术和实践，可以改进和演进我们的经典软件设计。这也特别关注于面向微服务的新范式开发。

作为 CNCF 的创始成员，谷歌已将 Kubernetes 开源项目捐赠为第一步。目标是增加生态系统中的互操作性，并支持与其他项目更好地集成。CNCF 已经在编排、日志记录、监控、追踪和应用程序弹性方面托管了各种项目。

有关 CNCF 的更多信息，请参阅[`cncf.io/.`](https://cncf.io/)

# 标准容器规范

OCI 努力的一个核心结果是创建和发展全面容器规范。该规范有五个所有容器都必须遵循的核心原则，我将简要概述一下（你可以在本章末尾的*参考资料*部分的第 2 点找到更多详细信息）：

+   容器必须具有在所有实现中创建、启动和停止容器的**标准操作**。

+   容器必须是**内容不可知**的，这意味着容器内部应用程序的类型不会改变容器本身的标准操作或发布。

+   容器也必须是**基础设施不可知**的。可移植性至关重要；因此，容器必须能够在 GCE 中与在公司数据中心或开发人员的笔记本电脑上同样轻松地运行。

+   一个容器还必须**设计用于自动化**，这使我们能够在构建、更新和部署流水线之间自动化。虽然这条规则有点模糊，但容器实现不应要求繁琐的手动步骤来创建和发布。

+   最后，实现必须支持**工业级交付**。再次，这涉及到构建和部署流水线，要求对容器在基础设施和部署层之间的可移植性和传输的高效流程。

规范还定义了容器格式和运行时的核心原则。你可以在 GitHub 项目上阅读更多有关规范的信息。

[`github.com/opencontainers/specs`](https://github.com/opencontainers/specs)

虽然核心规范可能有点抽象，但**runC**实现是 OCI 规范的具体示例，以容器运行时和镜像格式的形式呈现。你可以在以下网址的 runC 网站和 GitHub 上阅读更多技术细节：

+   [`github.com/opencontainers/runc`](https://github.com/opencontainers/runc)

+   [`runc.io/`](https://runc.io/)

一系列热门容器工具的支持格式和运行时基于**runC**。这是由 Docker 捐赠给 OCI 的，并且是从 Docker 平台中使用的相同基础工作创建的。自发布以来，它已被许多项目欢迎。

即使是流行的开源 PaaS，**Cloud Foundry**也宣布将在 Garden 中使用 runC。 Garden 为 Deigo 提供容器化基础设施，Deigo 则充当类似 Kubernetes 的编排层。

rkt 的实现最初基于**appc**规范。实际上，appc 规范是 CoreOS 团队早期尝试形成关于容器化的共同规范。现在 CoreOS 正在参与 OCI，并且正在努力将 appc 规范合并到 OCI 中；这应该会导致容器生态系统中更高水平的兼容性。

# CoreOS

虽然规范为我们提供了一个共同基础，但在我们容器的操作系统选择周围也有一些趋势正在演变。有几个特别为运行容器工作负载而开发的定制操作系统。尽管实现各不相同，但它们都具有类似的特征。专注于精简安装基础、原子操作系统更新和签名应用程序以实现高效和安全的运行。

正在受到欢迎的一个操作系统是**CoreOS**。CoreOS 在安全性和资源利用方面都提供了主要好处。它通过完全删除软件包依赖关系来提供资源利用。相反，CoreOS 将所有应用程序和服务都运行在容器中。通过仅提供支持运行容器所需的一小组服务，并且绕过使用虚拟化程序的需要，CoreOS 让我们能够使用更大比例的资源池来运行我们的容器化应用程序。这使得用户可以从他们的基础设施获得更高的性能和更好的容器与节点（服务器）使用比例。

**更多容器操作系统** 最近出现了几个其他容器优化的操作系统。

**Red Hat Enterprise Linux Atomic Host** 专注于安全性，默认启用 **SELinux** 并提供类似于 CoreOS 的 *Atomic* 更新操作系统。请参考以下链接：

网址为[`access.redhat.com/articles/rhel-atomic-getting-started`](https://access.redhat.com/articles/rhel-atomic-getting-started)

**Ubuntu Snappy** 也利用了将操作系统组件与框架和应用程序分离的效率和安全性提升。使用应用程序镜像和验证签名，我们可以获得一个高效的基于 Ubuntu 的操作系统，用于我们的容器工作负载，网址为[`www.ubuntu.com/cloud/tools/snappy`](http://www.ubuntu.com/cloud/tools/snappy)。

**Ubuntu LXD** 运行一个容器虚拟化程序，并提供了一个轻松迁移 Linux-based VMs 到容器的路径：

网址为[`www.ubuntu.com/cloud/lxd`](https://www.ubuntu.com/cloud/lxd)。

**VMware Photon** 是另一个针对 **vSphere** 和 VMware 平台进行优化的轻量级容器操作系统。它运行 Docker、rkt 和 Garden，并且还有一些可以在热门公共云提供商上运行的镜像。请参考以下链接：

网址为[`vmware.github.io/photon/`](https://vmware.github.io/photon/)。

利用容器的隔离性，我们增加了可靠性并降低了每个应用程序更新的复杂性。现在应用程序可以在每个新的容器发布准备就绪时与支持的库一起进行更新：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_11_01.png)

CoreOS 更新

最后，CoreOS 在安全领域还有一些额外的优势。首先，该操作系统可以作为一个整体单位进行更新，而不是通过单个软件包进行更新（参见上图）。这避免了许多由部分更新引起的问题。为了实现这一点，CoreOS 使用两个分区——一个作为活动的操作系统分区，另一个用于接收完整的更新。一旦更新成功完成，系统将重新启动并提升辅助分区。如果出现任何问题，原始分区可用于回退。

系统所有者还可以控制何时应用这些更新。这使我们可以灵活地优先考虑关键更新，同时与更常见的更新的实际调度一起工作。此外，整个更新都经过签名并通过 SSL 进行传输，以增加整个过程的安全性。

# rkt

CoreOS 生态系统的一个核心组成部分是它自己的容器运行时，名为 rkt。正如我们之前提到的，rkt 是另一种专注于安全性的实现。rkt 的主要优势在于以无守护程序的根用户身份运行引擎，就像 Docker 今天所做的那样。最初，rkt 在建立容器镜像的信任方面也有优势。然而，Docker 的最新更新通过新的**内容信任**功能取得了长足的进步。

简而言之，rkt 仍然是一个专注于在生产环境中运行容器的实现。rkt 使用一种名为**ACI**的图像格式，但它也支持运行基于 Docker 的图像。在过去的一年中，rkt 经历了重大更新，现在已经到了 1.24.0 版本。它作为在生产环境中安全运行 Docker 图像的方法已经获得了很大的动力。

此外，CoreOS 正在与**Intel®**合作，集成新的**Intel®虚拟化技术**，该技术允许容器在更高级别的隔离中运行。这种硬件增强的安全性允许容器在类似于当今我们看到的 hypervisors 的内核中运行，从而提供了与内核隔离相似的隔离。

# etcd

CoreOS 生态系统中另一个值得一提的核心组件是他们的开源 etcd 项目。etcd 是一个分布式且一致的键值存储。使用 RESTful API 与 etcd 进行接口交互，因此很容易与您的项目集成。

如果听起来很熟悉，那是因为我们在第一章中看到了这个过程，*Kubernetes 入门*，在*运行在主节点上的服务*部分。Kubernetes 实际上利用 etcd 来跟踪集群配置和当前状态。K8s 也利用它来进行服务发现。更多详情，请参阅[`github.com/coreos/etcd`](https://github.com/coreos/etcd)。

# 带有 CoreOS 的 Kubernetes

现在我们了解了这些好处，让我们来看一下使用 CoreOS 的 Kubernetes 集群。文档支持多个平台，但其中一个最容易启动的是使用 CoreOS **CloudFormation** 和 CLI 脚本的 AWS。

如果您有兴趣在其他平台上运行带有 CoreOS 的 Kubernetes，您可以在 CoreOS 文档中找到更多详情

[`coreos.com/kubernetes/docs/latest/`](https://coreos.com/kubernetes/docs/latest/)。 [](https://coreos.com/kubernetes/docs/latest/) 我们可以在这里找到 AWS 的最新说明

[`coreos.com/kubernetes/docs/latest/kubernetes-on-aws.html`](https://coreos.com/kubernetes/docs/latest/kubernetes-on-aws.html)。

您可以按照之前提到的说明在 CoreOS 上快速搭建 Kubernetes。您需要在 AWS 上创建一个密钥对，并指定一个区域、集群名称、集群大小和 DNS 以继续。

另外，我们需要创建一个 DNS 记录，并且需要一个像**Route53**这样的服务或者一个生产 DNS 服务。在按照说明操作时，您需要将 DNS 设置为您有权限设置记录的域或子域。在集群运行起来并且有定义动态端点后，我们需要更新记录。

就这样！我们现在有一个运行 CoreOS 的集群。该脚本创建了所有必要的 AWS 资源，例如**虚拟私有云**（**VPCs**）、安全组和 IAM 角色。现在集群已经运行起来，我们可以使用 `status` 命令获取端点并更新我们的 DNS 记录：

```
$ kube-aws status

```

复制紧挨着`Controller DNS Name`列出的条目，然后编辑您的 DNS 记录，将之前指定的域名或子域指向该负载均衡器。

如果您忘记了指定的域名，或者需要检查配置，可以使用您喜欢的编辑器查看生成的 `kubeconifg` 文件。它看起来会像这样：

```
apiVersion: v1
kind: Config
clusters:
- cluster:
    certificate-authority: credentials/ca.pem
    server: https://coreos.mydomain.com
  name: kube-aws-my-coreos-cluster-cluster
contexts:
- context:
    cluster: kube-aws-my-coreos-cluster-cluster
    namespace: default
    user: kube-aws-my-coreos-cluster-admin
  name: kube-aws-my-coreos-cluster-context
users:
- name: kube-aws-my-coreos-cluster-admin
  user:
    client-certificate: credentials/admin.pem
    client-key: credentials/admin-key.pem
current-context: kube-aws-my-coreos-cluster-context

```

在这种情况下，`server` 行将有您的域名。

如果这是一个新的服务器，您需要单独下载 `kubectl`，因为它没有与 `kube-aws` 捆绑在一起：

`**$ wget https://storage.googleapis.com/kubernetes-release/release/v1.0.6/bin/linux/amd64/kubectl**`

我们现在可以使用`kubectl`来查看我们的新集群：

```
$ ./kubectl --kubeconfig=kubeconfig get nodes

```

我们应该会看到一个节点列在 EC2 内部 DNS 作为名称。注意 `kubeconfig`，这告诉 Kubernetes 使用刚刚创建的集群的配置文件的路径。如果我们想要从同一台机器管理多个集群，这也很有用。

# Tect

在 CoreOS 上运行 Kubernetes 是一个很好的开始，但您可能会发现您需要更高级别的支持。来看看**Tectonic**，CoreOS 提供的用于在 CoreOS 上运行 Kubernetes 的企业级产品。Tectonic 使用了我们已经讨论过的许多组件。CoreOS 是操作系统，支持 Docker 和 rkt 运行时。此外，Kubernetes、etcd 和 flannel 被打包在一起，形成了一个完整的集群编排栈。我们在第三章简要讨论了 flannel，*网络、负载均衡器和入口*。它是一个覆盖网络，使用了类似于原生 Kubernetes 模型的模型，并将 etcd 用作后端。

类似于 Red Hat，CoreOS 还提供了类似的支持套餐，为构建在其上的开源软件 Tectonic 提供 24x7 支持。Tectonic 还提供定期的集群更新以及一个漂亮的仪表板，显示了 Kubernetes 的所有组件的视图。**CoreUpdate** 允许用户更多地控制自动更新。此外，它还提供了用于监控、SSO 和其他安全功能的模块。

您可以在此处找到更多信息以及最新的安装说明：

[`coreos.com/tectonic/docs/latest/install/aws/index.html`](https://coreos.com/tectonic/docs/latest/install/aws/index.html).

# 仪表板亮点

这里是 Tectonic 仪表板的一些亮点：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_11_02.png)

Tectonic 主仪表板

Tectonic 现在已经普遍可用，仪表板已经具有一些不错的功能。如下截图所示，我们可以看到关于我们的复制控制器的很多详细信息，甚至可以使用 GUI 通过点击按钮来进行上下缩放：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_11_03_Part1of2.png)

Tectonic 复制控制器详细信息

这个图形相当大，所以它跨两页显示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_11_03_Part2of2.png)

另一个很好的功能是 Events 页面。在这里，我们可以观看事件直播，暂停，并根据事件严重程度和资源类型进行筛选：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_11_04.png)

事件流

浏览仪表板系统中任何位置的一个有用功能是命名空间：过滤选项。只需点击显示资源的任何页面顶部旁边的下拉菜单旁边的“Namespace:”，我们就可以按命名空间筛选我们的视图。如果我们想要过滤掉 Kubernetes 系统 pod 或只查看特定的一组资源，这可能会有所帮助：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_11_05.png)

命名空间过滤

# 摘要

在本章中，我们看到了容器社区中新兴的标准机构，以及它们如何通过开放的规范来塑造技术，使其变得更好。我们还仔细研究了 CoreOS，这是容器和 Kubernetes 社区中的关键参与者。我们探索了他们正在开发的技术，以增强和补充容器编排，并亲自看到了如何在 Kubernetes 中使用其中的一些。最后，我们看了一下 Tectonic 的企业支持套件以及目前可用的一些功能。

在下一章，也就是最后一章中，我们将探讨更广泛的 Kubernetes 生态系统以及可用于将您的集群从开发和测试转移到完全成熟的生产环境的工具。

# 参考资料

1.  [`www.opencontainers.org/faq/`](https://www.opencontainers.org/faq/)（在 OCI 任务有多广泛? 下）

1.  [`github.com/opencontainers/specs/blob/master/principles.md`](https://github.com/opencontainers/specs/blob/master/principles.md)


# 第十二章：朝着生产就绪方向

在本章中，我们将讨论转向生产的考虑因素。我们还将展示 Kubernetes 社区中的一些有用工具和第三方项目，并介绍您可以获取更多帮助的地方。

本章将讨论以下主题：

+   生产特性

+   Kubernetes 生态系统

+   如何获得帮助？

# 准备就绪投入生产

我们通过 Kubernetes 进行了许多典型操作。正如我们所见，K8s 提供了各种功能和抽象，可以减轻容器部署的日常管理负担。

有许多特性定义了一个容器生产就绪系统。以下图表提供了一个高级视图，涵盖了生产就绪集群的主要关注点。这绝不是一个详尽的列表，但旨在为投入生产操作提供一些坚实的基础：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_12_01.png)

容器运行的生产特性

我们看到了 Kubernetes 的核心概念和抽象如何解决一些这些问题。服务抽象在服务和应用程序级别都内置了服务发现和健康检查。我们还从复制控制器和部署构造中获得无缝应用程序更新和可伸缩性。所有服务、复制控制器、副本集和 Pod 的核心抽象都与核心调度和亲和力规则集一起工作，并为我们提供了易于服务和应用程序组合的功能。

内置支持各种持久存储选项，并且网络模型提供了可管理的网络操作，并提供与其他第三方提供商合作的选项。此外，我们简要介绍了市场上一些热门工具与 CI/CD 集成。

此外，我们还内置了系统事件跟踪，并与主要云服务提供商集成，提供了监控和日志记录的即用即连设置。我们还看到了如何将这些扩展到第三方提供商，如**StackDriver**和**Sysdig**。这些服务还关注节点的整体健康状况，并提供主动的趋势偏差警报。

核心构建还帮助我们解决应用程序和服务层的高可用性问题。调度器可以与自动缩放机制一起在节点级别提供此功能。然后，支持使 Kubernetes 主节点本身高度可用。在第九章中，*集群联合*，我们简要介绍了承诺未来多云和多数据中心模型的新联合功能。

最后，我们探讨了一种新的操作系统类型，为我们提供了精简的基础和用于补丁和更新的安全更新机制。精简的基础，结合调度，可以帮助我们实现高效的资源利用。此外，我们还关注了一些加固问题，并探索了可用的图像信任和验证工具。安全性是一个广泛的话题，针对这个话题存在一系列功能矩阵。

# 准备好，开始吧

尽管仍有一些空白，剩余的安全性和运维问题正在被第三方公司积极解决，我们将在下一节中看到。未来，Kubernetes 项目将继续发展，周围的 K8s 和 Docker 项目以及合作伙伴社区也会不断壮大。社区正在以惊人的速度弥补剩余缺陷。

# 第三方公司

自 Kubernetes 项目最初发布以来，合作伙伴生态系统不断增长。我们在之前的章节中曾关注了 CoreOS、Sysdig 和许多其他公司，但在这个领域有各种项目和公司。我们将突出一些可能在您向生产环境迈进时有用的项目。这绝对不是一个详尽的清单，只是为了提供一些有趣的起点。

# 私有注册表

在许多情况下，组织可能不希望将他们的应用程序和/或知识产权放入公共存储库中。对于这些情况，私有注册表解决方案有助于在端到端安全地集成部署。

谷歌云提供 **Google Container Registry** [`cloud.google.com/container-registry/`](https://cloud.google.com/container-registry/)。

Docker 提供了自己的 **Trusted Registry** [`www.docker.com/docker-trusted-registry`](https://www.docker.com/docker-trusted-registry)。

**Quay.io** 也提供安全的私有注册表、漏洞扫描，并来自 CoreOS 团队 [`quay.io/`](https://quay.io/)。

# 谷歌容器引擎

谷歌是原始 Kubernetes 项目的主要作者，仍然是主要贡献者。尽管本书主要关注在我们自己运行 Kubernetes，谷歌还通过 Google 云平台提供了一个完全托管的容器服务。

在 **Google Container Engine** (**GKE**) 网站上找到更多信息 [`cloud.google.com/container-engine/`](https://cloud.google.com/container-engine/)。

[`cloud.google.com/container-engine/`](https://cloud.google.com/container-engine/)。

Kubernetes 将安装在 GCE 上，并由 Google 工程师进行管理。他们还提供私有注册表和与现有私有网络集成。

**创建您的第一个 GKE 集群** 从 GCP 控制台，在 Compute 中，点击容器引擎，然后点击容器集群。

如果这是您第一次创建集群，在页面中间会有一个信息框。点击创建一个容器集群按钮。

为您的集群和区域选择一个名称。您还将能够为您的节点选择机器类型（实例大小）和您希望在您的集群中有多少个节点（集群大小）。您还将看到一个节点镜像的选择，它让您可以为节点自身选择基础操作系统和机器镜像。主节点由 Google 团队自行管理和更新。保留 Stackdriver Logging 和 Stackdriver Monitoring 勾选状态。单击创建，几分钟后，您将拥有一个新的可以使用的集群。

您需要使用包含在 Google SDK 中的 `kubectl` 来开始使用您的 GKE 集群。有关安装 SDK 的详细信息，请参阅 第一章，*Kubernetes 简介*。一旦我们有了 SDK，我们可以使用以下步骤为我们的集群配置 `kubectl` 和 SDK

[`cloud.google.com/container-engine/docs/before-you-begin#install_kubectl`](https://cloud.google.com/container-engine/docs/before-you-begin#install_kubectl).

# Azure 容器服务

另一个云托管的选择是微软的**Azure 容器服务**（**ACS**）。ACS 非常好，因为它允许您选择诸如 Docker Swarm、Kubernetes 和 Mesos 等行业标准工具。然后，它为您创建一个托管的集群，但使用其中一个工具集作为基础。优点是您仍然可以使用工具的本机 API 和管理工具，但将云基础设施的管理留给 Azure。

了解有关 ACS 的更多信息

[`azure.microsoft.com/en-us/services/container-service/`](https://azure.microsoft.com/en-us/services/container-service/).

# ClusterHQ

ClusterHQ 提供了一种将有状态数据引入您的容器化应用的解决方案。他们提供 Flocker，这是一个用于管理容器持久性存储卷的工具，以及 FlockerHub，为您的数据卷提供存储库。

请参考 ClusterHQ 网站以获取更多信息。

[`clusterhq.com/`](https://clusterhq.com/).

# Portworx

Portworx 是存储领域的另一家参与者。它提供了将持久性存储引入您的容器的解决方案。此外，它还具有用于快照、加密甚至多云复制的功能。

请参考 portworx 网站以获取更多信息。

[`portworx.com/`](https://portworx.com/).

# Shippable

Shippable 是一个持续集成、持续部署和发布自动化平台，内置对各种现代容器环境的支持。该产品标榜支持任何语言，并统一支持打包和测试。

请参考 Shippable 网站以获取更多信息。

[`app.shippable.com/`](https://app.shippable.com/).

# Twistlock

**Twistlock.io** 是一个专为容器量身定制的漏洞和加固工具。它提供了执行策略的能力，根据 CIS 标准进行加固，并扫描任何流行注册表中的图像以查找漏洞。它还提供了与流行 CI/CD 工具的扫描集成，以及为诸如 Kubernetes 等编排工具的 RBAC 解决方案。

请参考 Twistlock 网站获取更多信息。

[`www.twistlock.io/`](https://www.twistlock.io/)。

# AquaSec

AquaSec 是另一个提供各种功能的安全工具。它与流行注册表的图像扫描、策略执行、用户访问控制和容器加固等功能都有涉及。此外，AquaSec 在网络分割方面还具有一些有趣的功能。

请参考 Aqua 的网站获取更多信息。

[`www.aquasec.com/`](https://www.aquasec.com/)。

# Mesosphere（Kubernetes on Mesos）

**Mesosphere** 本身正在围绕开源的 Apache Mesos 项目构建一个商业支持的产品（**DCOS**）。**Apache Mesos** 是一个类似于 Kubernetes 的集群管理系统，提供调度和资源共享，但在更高的层面上。这个开源项目被一些知名公司使用，如 **Twitter** 和 **AirBnB**。

在这些网站上获取有关 Mesos OS 项目和 Mesosphere 提供的更多信息：

+   [`mesos.apache.org/`](http://mesos.apache.org/)

+   [`mesosphere.com/`](https://mesosphere.com/)

由于 Mesos 的模块化特性，它允许在各种平台上使用不同的框架。现在已经有了一个 Kubernetes 框架，所以我们可以利用 Mesos 中的集群管理，同时保持 K8s 中有用的应用级抽象。请参考以下链接：

[`github.com/kubernetes-incubator/kube-mesos-framework`](https://github.com/kubernetes-incubator/kube-mesos-framework)

# Deis

**Deis** 项目提供了基于 Kubernetes 的开源**平台即服务**（**PaaS**）解决方案。这使得公司可以在本地部署或在公共云上部署他们自己的 PaaS。Deis 提供了应用程序组合和部署工具，包管理（在 pod 级别），以及服务经纪等功能。

您可以参考以下网站了解更多关于 Deis 的信息：

[`deis.com/`](https://deis.com/)。

# OpenShift

另一个 PaaS 解决方案是来自红帽的 **OpenShift**。OpenShift 平台使用红帽 Atomic 平台作为运行容器的安全且轻量的操作系统。在第 3 版中，Kubernetes 被添加为在 PaaS 上进行所有容器操作的编排层。这是一个管理大规模 PaaS 安装的绝佳组合。

关于 OpenShift 的更多信息，请访问 [`enterprise.openshift.com/.`](https://enterprise.openshift.com/)

# 想了解更多？

Kubernetes 项目是一个开源项目，因此有广泛的贡献者和爱好者社区。要找到更多帮助的资源之一是 Kubernetes **Slack** 频道：[`slack.kubernetes.io/`](http://slack.kubernetes.io/)

Google 群组中还有一个 Kubernetes 群组。你可以加入它

[`groups.google.com/forum/#!forum/kubernetes-users`](https://groups.google.com/forum/#!forum/kubernetes-users)。

如果你喜欢这本书，你可以在我的博客和 Twitter 页面上找到更多我的文章、操作指南和各种思考：

+   [`medium.com/@grizzbaier`](https://medium.com/@grizzbaier)

+   [`twitter.com/grizzbaier`](https://twitter.com/grizzbaier)

# 摘要

在这最后一章中，我们留下了一些线索，引导你继续你的 Kubernetes 之旅。你应该有一套坚实的生产特性来帮助你入门。在 Docker 和 Kubernetes 的世界中有一个广泛的社区。如果需要在旅途中有一个友好的面孔，我们还提供了一些额外的资源。

到目前为止，我们已经看到了 Kubernetes 的容器操作的全景。你应该对 Kubernetes 如何简化容器部署的管理以及如何计划将容器从开发人员的笔记本迁移到生产服务器上有更多信心。现在出发，开始部署你的容器吧！
