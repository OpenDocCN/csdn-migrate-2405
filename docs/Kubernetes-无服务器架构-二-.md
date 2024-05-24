# Kubernetes 无服务器架构（二）

> 原文：[`zh.annas-archive.org/md5/36BD40FEB49D3928DE19F4A0B653CB1B`](https://zh.annas-archive.org/md5/36BD40FEB49D3928DE19F4A0B653CB1B)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章： 生产就绪的 Kubernetes 集群

## 学习目标

本章结束时，您将能够：

+   识别 Kubernetes 集群设置的要求

+   在 Google Cloud Platform（GCP）中创建一个生产就绪的 Kubernetes 集群

+   管理集群自动缩放以向 Kubernetes 集群添加新服务器

+   迁移生产集群中的应用程序

在本章中，我们将学习关于设置 Kubernetes 的关键考虑因素。随后，我们还将研究不同的 Kubernetes 平台选项。然后，我们将继续在云平台上创建一个生产就绪的 Kubernetes 集群，并执行管理任务。

## 介绍

在上一章中，我们为开发环境创建了 Kubernetes 集群，并将应用程序安装到其中。在本章中，重点将放在生产就绪的 Kubernetes 集群上，以及如何管理它们以获得更好的可用性、可靠性和成本优化。

Kubernetes 是在云中管理作为容器运行的微服务的事实标准系统。它被行业广泛采用，包括初创公司和大型企业，用于运行各种类型的应用程序，包括数据分析工具、无服务器应用程序和数据库。可伸缩性、高可用性、可靠性和安全性是 Kubernetes 的关键特性，使其能够被广泛采用。假设您已决定使用 Kubernetes，因此您需要一个可靠且可观察的集群设置用于开发和生产。在选择 Kubernetes 提供商以及如何操作应用程序之前，有一些关键的考虑因素取决于您的需求、预算和团队。有四个关键考虑因素需要分析：

+   **服务质量：** Kubernetes 以*高可用*和可靠的方式运行微服务。然而，安装和可靠地操作 Kubernetes 至关重要。假设您已将 Kubernetes 控制平面安装到集群中的单个节点，并且由于网络问题而断开连接。由于您已经失去了 Kubernetes API 服务器的连接，您将无法检查应用程序的状态和操作它们。因此，评估您在生产环境中所需的 Kubernetes 集群的服务质量至关重要。

+   **监控：** Kubernetes 运行分布到节点的容器，并能够检查它们的日志和状态。假设您昨天推出了应用程序的新版本。今天，您想要检查最新版本的运行情况，是否有错误、崩溃和响应时间。因此，您需要一个集成到 Kubernetes 集群中的监控系统来捕获日志和指标。收集的数据对于生产就绪的集群中的故障排除和诊断至关重要。

+   **安全性：** Kubernetes 组件和客户端工具以安全的方式工作，以管理集群中运行的应用程序。然而，您需要为您的组织定义特定的角色和授权级别，以安全地操作 Kubernetes 集群。因此，选择一个可以安全连接并与客户和同事共享的 Kubernetes 提供者平台至关重要。

+   **运维：** Kubernetes 是所有应用程序的主机，包括具有数据合规性、审计和企业级要求的服务。假设您正在 Kubernetes 上运行在线银行应用系统的后端和前端。对于您所在国家的特许银行，应用程序的审计日志应该是可访问的。由于您已经在 Kubernetes 上部署了整个系统，平台应该能够获取审计日志、存档和存储它们。因此，Kubernetes 平台的运维能力对于生产就绪的集群设置至关重要。

为了决定如何安装和操作您的 Kubernetes 集群，本章将讨论这些考虑因素，以选择 Kubernetes 平台选项。

## Kubernetes 设置

Kubernetes 是一个灵活的系统，可以安装在各种平台上，从**树莓派**到**数据中心**中的高端服务器。每个平台在服务质量、监控、安全性和运营方面都有其优势和劣势。Kubernetes 将应用程序作为容器进行管理，并在基础架构上创建一个抽象层。假设你在地下室的三台旧服务器上安装了 Kubernetes，然后安装了你的新项目的**概念验证**（**PoC**）。当项目取得成功后，你想要扩展你的应用程序并迁移到**亚马逊网络服务**（**AWS**）等云服务提供商。由于你的应用程序是设计运行在 Kubernetes 上，并且不依赖于基础设施，因此迁移到另一个 Kubernetes 安装是直接的。

在上一章中，我们学习了使用`minikube`作为 Kubernetes 的官方方法来设置开发环境。在本节中，将介绍生产级别的 Kubernetes 平台。生产级别的 Kubernetes 平台可以分为三种，具有以下抽象层：

![图 5.1：Kubernetes 平台](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_05_01.jpg)

###### 图 5.1：Kubernetes 平台

现在让我们逐个看看这些类型。

### 托管平台

托管平台提供**Kubernetes 作为服务**，所有底层服务都在云提供商的控制下运行。由于云提供商处理所有基础设施操作，因此设置和扩展这些集群非常容易。领先的云提供商，如 GCP、AWS 和 Microsoft Azure，都提供了托管的 Kubernetes 解决方案应用程序，旨在集成其他云服务，如容器注册表、身份服务和存储服务。最受欢迎的托管 Kubernetes 解决方案如下：

+   **Google Kubernetes Engine (GKE):** GKE 是市场上最成熟的托管服务，谷歌将其作为 GCP 的一部分提供。

+   **Azure Kubernetes Service (AKS):** AKS 是微软提供的作为 Azure 平台一部分的 Kubernetes 解决方案。

+   **Amazon 弹性容器服务（EKS）：** EKS 是 AWS 的托管 Kubernetes。

### 即插即用平台

即插即用解决方案专注于在云端或内部系统中安装和操作 Kubernetes 控制平面。即插即用平台的用户提供有关基础设施的信息，即插即用平台处理 Kubernetes 设置。即插即用平台在设置配置和基础设施选项方面提供更好的灵活性。这些平台大多由在 Kubernetes 和云系统方面拥有丰富经验的组织设计，如**Heptio**或**CoreOS**。

如果将即插即用平台安装在 AWS 等云提供商上，基础设施由云提供商管理，即插即用平台管理 Kubernetes。然而，当即插即用平台安装在内部系统上时，内部团队应处理基础设施运营。

### 自定义平台

如果您的用例不适用于任何托管或即插即用解决方案，则可以进行自定义安装 Kubernetes。例如，您可以使用**Gardener**（https://gardener.cloud）或**OpenShift**（https://www.openshift.com）在云提供商、内部数据中心、内部虚拟机（VM）或裸金属服务器上安装 Kubernetes 集群。虽然自定义平台提供更灵活的 Kubernetes 安装，但也需要特殊的运营和维护工作。

在接下来的章节中，我们将在 GKE 中创建一个托管的 Kubernetes 集群并对其进行管理。GKE 提供了市场上最成熟的平台和卓越的客户体验。

## Google Kubernetes Engine

GKE 提供了一个由 Google 在运行容器化服务方面拥有十多年经验支持的托管 Kubernetes 平台。GKE 集群已经准备就绪并且可扩展，并支持上游 Kubernetes 版本。此外，GKE 专注于通过消除 Kubernetes 集群的安装、管理和运营需求来改善开发体验。

虽然 GKE 改善了开发者体验，但它试图最小化运行 Kubernetes 集群的成本。它只收取集群中的节点费用，并免费提供 Kubernetes 控制平面。换句话说，GKE 提供了一个可靠、可扩展和强大的 Kubernetes 控制平面，而没有任何费用。对于运行应用程序工作负载的服务器，通常适用 GCP 计算引擎定价。例如，假设您将从两个`n1-standard-1` **（vCPUs：1，RAM：3.75 GB）**节点开始：

计算如下：

每月总计 1,460 小时

**实例类型**：n1-standard-1

**GCE 实例成本**：48.54 美元

**Kubernetes Engine 成本**：0.00 美元

**预估组件成本**：每月 48.54 美元

如果您的应用程序需要随着更高的使用量而扩展，如果您需要 10 台服务器而不是 2 台，成本也会线性增加：

每月总共 7300 小时

**实例类型**：n1-standard-1

**GCE 实例成本**：242.72 美元

**Kubernetes Engine Cost**: USD 0.00

**预估组件成本**：每月 242.72 美元

这个计算表明，GKE 不会为 Kubernetes 控制平面收费，并为每个集群提供可靠、可扩展和强大的 Kubernetes API。此外，扩展集群的成本是线性增加的，这使得规划和操作 Kubernetes 集群变得更加容易。

在接下来的练习中，您将在 GKE 中创建一个托管的 Kubernetes 集群并连接到它。

#### 注意

为了完成这个练习，您需要有一个活跃的 GCP 账户。您可以在其官方网站上创建一个账户：https://console.cloud.google.com/start。

### 练习 13：在 GCP 上创建 Kubernetes 集群

在这个练习中，我们将在 GKE 中创建一个 Kubernetes 集群，并安全地连接到它以检查节点状态。Google Cloud Platform 的仪表板和 CLI 工具保持了高水平的开发者体验。因此，如果您需要一个生产就绪的 Kubernetes 集群，您将在不到 10 分钟内拥有一个完全运行的控制平面和服务器节点。

为了完成练习，我们需要确保执行以下步骤：

1.  在 Google Cloud Platform 主页的**计算**下的左侧菜单中点击**Kubernetes Engine**，如下图所示：![图 5.2：Google Cloud Platform 主页](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_05_02.jpg)

###### 图 5.2：Google Cloud Platform 主页

1.  在**集群**页面上点击**创建集群**，如下图所示：![图 5.3：集群视图](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_05_03.jpg)

###### 图 5.3：集群视图

1.  在**集群模板**中从左侧选择**您的第一个集群**，并将`serverless`作为名称。点击页面底部的**创建**，如下图所示：![图 5.4：集群创建](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_05_04.jpg)

###### 图 5.4：集群创建

1.  等待几分钟，直到集群图标变成绿色，然后点击**连接**按钮，如下图所示：![图 5.5：集群列表](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_05_05.jpg)

###### 图 5.5：集群列表

1.  点击**在云 shell 中运行**在**连接到集群**窗口中，如下图所示：![图 5.6：连接到集群视图](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_05_06.jpg)

###### 图 5.6：连接到集群视图

1.  等到云 shell 打开并可用时，按下*Enter*，当命令显示时，如下图所示：![图 5.7：云 shell](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_05_07.jpg)

###### 图 5.7：云 shell

输出显示，集群的认证数据已被获取，**kubeconfig**条目已准备就绪。

1.  在云 shell 中使用以下命令检查节点：

```
kubectl get nodes
```

由于集群是使用一个节点池创建的，只有一个节点连接到集群，如下图所示：

![图 5.8：节点列表](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_05_08.jpg)

###### 图 5.8：节点列表

1.  在云 shell 中使用以下命令检查集群中运行的 pod：

```
kubectl get pods --all-namespaces
```

由于 GKE 管理控制平面，在`kube-system`命名空间中没有`api-server`、`etcd`或`scheduler`的 pod。集群中只有网络和指标的 pod 在运行，如下截图所示：

![图 5.9：Pod 列表](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_05_09.jpg)

###### 图 5.9：Pod 列表

通过这个练习，您已经在 GKE 上创建了一个生产就绪的 Kubernetes 集群。在几分钟内，GKE 创建了一个托管的 Kubernetes 控制平面，并将服务器连接到了集群。在接下来的章节中，将讨论管理生产环境中的集群，并扩展这个练习中的 Kubernetes 集群。

## 自动缩放 Kubernetes 集群

Kubernetes 集群旨在可靠地运行可扩展的应用程序。换句话说，如果 Kubernetes 集群今天运行您的应用程序的**10 个实例**，它也应该支持在未来运行**100 个实例**。有两种主流方法可以达到这种灵活性水平：*冗余*和*自动缩放*。假设您的应用程序的 10 个实例正在集群中的 3 台服务器上运行。通过冗余，您至少需要 27 台额外的空闲服务器来在未来运行 100 个实例。这也意味着支付空闲服务器的费用以及运营和维护成本。通过自动缩放，您需要自动化程序来创建或删除服务器。自动缩放确保没有过多的空闲服务器，并最大程度地减少成本，同时满足可扩展性要求。

**GKE 集群自动缩放器**是处理 Kubernetes 集群中自动缩放的开箱即用解决方案。启用后，如果工作负载没有剩余容量，它会自动添加新服务器。同样，当服务器利用率不足时，自动缩放器会删除多余的服务器。此外，自动缩放器还定义了服务器的最小和最大数量，以避免无限增加或减少。在以下练习中，将为 Kubernetes 集群启用 GKE 集群自动缩放器。然后通过更改集群中的工作负载来演示服务器的自动缩放。

### 练习 14：在生产环境中为 GKE 集群启用自动缩放

在本练习中，我们将在生产集群中启用并利用 GKE 集群自动缩放器。假设您需要在集群中运行大量应用的副本。但是，由于服务器数量较少，目前不可能实现。因此，您需要启用自动缩放，并查看如何自动创建新服务器。

要成功完成练习，我们需要确保执行以下步骤：

1.  通过在云 shell 中运行以下命令在集群中安装`nginx`：

```
kubectl create deployment workload --image=nginx 
```

此命令从`nginx`镜像创建名为`workload`的部署，如下图所示：

![图 5.10：部署创建](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_05_10.jpg)

###### 图 5.10：部署创建

1.  通过在云 shell 中运行以下命令将`workload`部署扩展到 25 个副本：

```
kubectl scale deployment workload --replicas=25
```

此命令增加了 workload 部署的副本数量，如下图所示：

![图 5.11：部署扩展](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_05_11.jpg)

###### 图 5.11：部署扩展

1.  使用以下命令检查运行中的 pod 数量：

```
kubectl get deployment workload
```

由于集群中只有 1 个节点，因此无法在集群中运行 25 个`nginx`的副本。相反，目前只有 5 个实例正在运行，如下图所示：

![图 5.12：部署状态](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_05_12.jpg)

###### 图 5.12：部署状态

1.  使用以下命令为集群的节点池启用自动扩展：

```
gcloud container clusters update serverless --enable-autoscaling  \
 --min-nodes 1 --max-nodes 10 --zone us-central1-a  \
 --node-pool pool-1
```

#### 注意

如果您的集群在另一个区域运行，请更改`zone`参数。

此命令启用了 Kubernetes 集群的自动扩展，最小节点数为 1，最大节点数为 10，如下图所示：

![图 5.13：启用自动缩放器](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_05_13.jpg)

###### 图 5.13：启用自动缩放器

此命令可能需要几分钟的时间来创建所需的资源，并显示“正在更新无服务器...”提示。

1.  等待几分钟，然后使用以下命令检查节点数：

```
kubectl get nodes
```

启用自动缩放后，GKE 确保集群中有足够的节点来运行工作负载。节点池扩展到四个节点，如下图所示：

![图 5.14：节点列表](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_05_14.jpg)

###### 图 5.14：节点列表

1.  使用以下命令检查运行中的 pod 数量：

```
kubectl get deployment workload
```

由于集群中有 4 个节点，因此可以在集群中运行 25 个`nginx`的副本，如下图所示：

![图 5.15：部署状态](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_05_15.jpg)

###### 图 5.15：部署状态

1.  使用以下命令删除部署：

```
kubectl delete deployment workload
```

输出应该如下所示：

![图 5.16：部署删除](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_05_16.jpg)

###### 图 5.16：部署删除

1.  使用以下命令禁用集群的节点池的自动缩放：

```
gcloud container clusters update serverless --no-enable-autoscaling \
--node-pool pool-1 --zone us-central1-a
```

#### 注意

如果您的集群在另一个区域运行，请更改`zone`参数。

您应该看到以下图中显示的输出：

![图 5.17：禁用自动缩放](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_05_17.jpg)

###### 图 5.17：禁用自动缩放

在这个练习中，我们看到了 GKE 集群自动缩放器的运行情况。当自动缩放器启用时，它会在集群对当前工作负载容量不足时增加服务器数量。尽管看起来很简单，但这是 Kubernetes 平台的一个引人注目的特性。它消除了手动操作的负担，以检查集群利用率并采取行动。对于用户需求变化很大的无服务器应用程序来说，这一点甚至更为关键。

假设您已经在 Kubernetes 集群中部署了一个启用了自动缩放的无服务器函数。当您的函数频繁调用时，集群自动缩放器将自动增加节点数量，然后在您的函数不被调用时删除节点。因此，检查 Kubernetes 平台对无服务器应用程序的自动缩放能力是至关重要的。在接下来的部分中，将讨论在生产环境中迁移应用程序，这是另一个重要的集群管理任务。

## Kubernetes 集群中的应用迁移

Kubernetes 将应用程序分发到服务器并保持它们可靠和稳健地运行。集群中的服务器可以是具有不同技术规格的 VM 或裸金属服务器实例。假设您只连接了标准 VM 到您的 Kubernetes 集群，并且它们正在运行各种类型的应用程序。如果您即将使用的数据分析库需要 GPU 来更快地运行，您需要连接具有 GPU 的服务器。同样，如果您的数据库应用程序需要 SSD 磁盘来进行更快的 I/O 操作，您需要连接具有 SSD 访问权限的服务器。这些应用程序要求导致在集群中有不同的节点池。此外，您需要配置 Kubernetes 工作负载在特定节点上运行。除了标记一些节点保留给特殊类型的工作负载外，还使用了污点。同样，如果 pod 运行特定类型的工作负载，它们将被标记为容忍。Kubernetes 支持使用污点和容忍度协同工作来将工作负载分发到特殊节点。

+   污点是应用于节点的，表示该节点不应该有任何不容忍污点的 pod。

+   容忍度被应用于 pod，允许 pod 被调度到具有污点的节点上。

例如，如果您只想在具有 SSD 的节点上运行数据库实例，您需要首先对节点进行污点处理：

```
kubectl taint nodes disk-node-1 ssd=true:NoSchedule
```

使用这个命令，`disk-node-1`将只接受具有以下容忍度的 pod：

```
tolerations:
- key: "ssd"
  operator: "Equal"
  value: "true"
  effect: "NoSchedule"
```

污点和容忍度协同工作，作为 Kubernetes 调度器的一部分，将 pod 分配给特定的节点。此外，Kubernetes 支持使用`kubectl drain`命令安全地从集群中移除服务器。如果您想对一些节点进行维护或退役，这将非常有帮助。在下面的练习中，运行在 Kubernetes 集群中的应用程序将迁移到一组特定的新节点。

### 练习 15：迁移在 GKE 集群中运行的应用程序

这个练习旨在教我们在生产集群中执行迁移活动。假设您在 Kubernetes 集群中运行一个后端应用程序。随着最近的变化，您已经改进了应用程序的内存管理，并希望在具有更高内存优化的服务器上运行。因此，您将创建一个新的节点池，并将应用程序实例迁移到其中。

为了成功完成练习，我们需要确保执行以下步骤：

1.  通过在云 shell 中运行以下命令将后端应用程序安装到集群中：

```
kubectl create deployment backend --image=nginx 
```

此命令从`nginx`镜像创建名为`backend`的部署，如下图所示：

![图 5.18：部署创建](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_05_18.jpg)

###### 图 5.18：部署创建

1.  通过在云 shell 中运行以下命令，将`backend`部署的副本数扩展到`10`：

```
    kubectl scale deployment backend --replicas=10    
```

此命令增加了后端部署的副本数，如下图所示：

![图 5.19：部署扩展](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_05_19.jpg)

###### 图 5.19：部署扩展

1.  使用以下命令检查正在运行的`pods`数量及其节点：

```
kubectl get pods -o wide
```

部署的所有 10 个副本都在 4 个节点上成功运行，如下图所示：

![图 5.20：部署状态](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_05_20.jpg)

###### 图 5.20：部署状态

1.  在 GCP 中创建一个具有更高内存的节点池：

```
gcloud container node-pools create high-memory-pool --cluster=serverless \
--zone us-central1-a --machine-type=n1-highmem-2 --num-nodes=2
```

#### 注意

如果您的集群在另一个区域运行，请更改`zone`参数。

此命令在无服务器集群中创建了一个名为`high-memory-pool`的新节点池，机器类型为`n1-highmem-2`，有两个服务器，如下图所示：

![图 5.21：节点池创建](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_05_21.jpg)

###### 图 5.21：节点池创建

此命令可能需要几分钟来创建所需的资源，并显示**创建节点池高内存池**提示。

1.  等待几分钟并检查集群中的节点：

```
kubectl get nodes
```

此命令列出了集群中的节点，我们期望看到两个额外的`high-memory`节点，如下图所示：

![图 5.22：集群节点](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_05_22.jpg)

###### 图 5.22：集群节点

1.  排空旧节点，以便 Kubernetes 将应用程序迁移到新节点：

```
kubectl drain -l cloud.google.com/gke-nodepool=pool-1
```

此命令从所有带有标签`cloud.google.com/gke-nodepool=pool-1`的节点中删除工作负载，如下图所示：

![图 5.23：节点移除](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_05_23.jpg)

###### 图 5.23：节点移除

1.  使用以下命令检查正在运行的 pods 及其节点：

```
kubectl get pods -o wide
```

部署的所有 10 个副本都成功运行在新的`high-memory`节点上，如下图所示：

![图 5.24：部署状态](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_05_24.jpg)

###### 图 5.24：部署状态

1.  使用以下命令删除旧的节点池：

```
gcloud container node-pools delete pool-1 --cluster serverless --zone us-central1-a 
```

#### 注意

更改`zone`参数，如果您的集群在另一个区域运行。

此命令将删除未使用的旧节点池，如下图所示：

![图 5.25：节点池删除](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_05_25.jpg)

###### 图 5.25：节点池删除

在这个练习中，我们已经将正在运行的应用迁移到了具有更好技术规格的新节点。使用 Kubernetes 原语和 GKE 节点池，可以在没有停机时间的情况下将应用迁移到特定的节点集。在接下来的活动中，您将使用自动缩放和 Kubernetes 污点来运行无服务器函数，同时最大限度地降低成本。

### 活动 5：在 GKE 集群中最大限度地降低无服务器函数的成本

本活动的目的是在生产集群上执行管理任务，以运行无服务器函数，同时最大限度地降低成本。假设您的后端应用已经在 Kubernetes 集群中运行。现在，您希望安装一些无服务器函数来连接后端。然而，后端实例正在运行内存优化的服务器，这对于运行无服务器函数也是昂贵的。因此，您需要添加*可抢占*服务器，这些服务器更便宜。可抢占 VM 已经在 GCP 中可用；然而，它们具有较低的服务质量和最长寿命为 24 小时。因此，您应该配置节点池为自动缩放，并且只运行无服务器函数。否则，您的后端实例也可能被调度到可抢占 VM 上，并降低整体性能。

活动结束时，您将拥有连接到后端实例的函数，如下图所示：

![图 5.26：后端检查器功能](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_05_26.jpg)

###### 图 5.26：后端检查器功能

后端实例将在高内存节点上运行，功能实例将在可抢占服务器上运行，如下图所示：

![图 5.27：Kubernetes pods 和相应的节点](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_05_27.jpg)

###### 图 5.27：Kubernetes pods 和相应的节点

#### 注意

为了完成活动，您应该使用来自*练习 15*的集群，其中运行着后端部署。

执行以下步骤完成活动：

1.  创建一个具有可抢占服务器的新节点池。

1.  给可抢占服务器打上标记，只运行无服务器函数。

1.  创建一个 Kubernetes 服务以访问后端 pod。

1.  创建一个 CronJob，每分钟连接到后端服务。CronJob 定义应该具有容忍性，可以在可抢占服务器上运行。

1.  检查 CronJob 函数的节点分配。

1.  检查 CronJob 函数实例的日志。

1.  清理后端部署和无服务器函数。

1.  如果不再需要 Kubernetes 集群，请将其删除。

#### 注意

活动的解决方案可以在第 412 页找到。

## 摘要

在本章中，我们首先描述了分析 Kubernetes 集群设置要求的四个关键考虑因素。然后我们研究了三组 Kubernetes 平台：托管、即插即用和定制。每个 Kubernetes 平台都有解释，以及它们在基础设施、Kubernetes 和应用程序上的责任水平。在那之后，我们在 GKE 上创建了一个可投入生产的 Kubernetes 集群。由于 Kubernetes 旨在运行可扩展的应用程序，我们研究了如何通过自动缩放来处理工作负载的增加或减少。此外，我们还研究了在生产集群中无需停机的应用程序迁移，以说明如何将应用程序移动到具有更高内存的服务器。最后，我们在生产集群中运行无服务器函数来执行自动缩放和迁移活动，以最大程度地降低成本。Kubernetes 和无服务器应用程序共同工作，创建可靠、强大和可扩展的未来环境。因此，了解如何安装和操作生产环境的 Kubernetes 集群至关重要。

在下一章中，我们将研究 Kubernetes 中即将推出的无服务器功能。我们还将详细研究虚拟 kubelet，并在 GKE 上部署无状态容器。


# 第六章： Kubernetes 中即将推出的无服务器功能

## 学习目标

在本章结束时，您将能够：

+   利用 Knative 的概念和组件部署应用程序

+   在 GKE 集群上设置 Knative

+   在 Knative 上部署应用程序并配置自动缩放

+   在谷歌云运行上部署应用程序

+   在 Azure 上设置虚拟 Kubelet

+   使用虚拟 Kubelet 部署应用程序

本章涵盖了 Knative、谷歌云运行和虚拟 Kubelet，它们在 Kubernetes 集群之上提供了无服务器的优势。

## 介绍 Kubernetes 的无服务器功能

在上一章中，我们广泛研究了 Kubernetes 中使用的各种设置选项和平台。我们还涵盖了 Kubernetes 的自动缩放功能，并在集群上部署的应用程序中实施了它。

Kubernetes 和无服务器是 IT 行业中的两个热门话题，但这两个话题经常被独立讨论。Kubernetes 是一个管理容器化应用程序的平台，而无服务器是一种执行模型，它抽象了基础设施，使软件开发人员可以专注于他们的应用逻辑。然而，这两个概念的结合将实现同样的目标，使软件开发人员的生活变得更加轻松。

最近出现了一些平台，通过抽象管理容器和任何基础架构的复杂性，为容器带来了无服务器特性。这些平台在 Kubernetes 集群上运行无服务器工作负载，并提供许多好处，包括自动缩放、零缩放、按使用量计费、事件驱动功能、集成监控和集成日志记录功能。

在本章中，我们将讨论三种技术，它们在 Kubernetes 集群之上提供了无服务器的好处：

+   Knative

+   谷歌云运行

+   虚拟 Kubelet

### Knative 简介

Knative 是由谷歌发起的开源项目，得到了包括 Pivotal、Red Hat、IBM 和 SAP 在内的 50 多家其他公司的贡献。Knative 通过引入一组组件来扩展 Kubernetes，从而构建和运行无服务器应用程序。这个框架非常适合已经在使用 Kubernetes 的应用开发人员。Knative 为他们提供了工具，让他们专注于他们的代码，而不用担心 Kubernetes 的底层架构。它引入了自动化容器构建、自动缩放、零缩放和事件框架等功能，使开发人员能够在 Kubernetes 之上获得无服务器的好处。

Knative 框架在 Knative 网站上被描述为“*基于 Kubernetes 的平台，用于部署和管理现代无服务器工作负载*”。该框架通过引入无服务器特性，如自动缩放和零缩放，来弥合容器化应用程序和无服务器应用程序之间的差距。

Knative 由三个主要组件组成：

+   构建

+   服务

+   事件

#### 注意

在最新版本的 Knative 中，构建组件已被弃用，而是更倾向于使用 Tekton Pipelines。Knative 构建组件的最终版本可在 0.7 版本中获得。

构建是从源代码构建容器映像并在 Kubernetes 集群上运行它们的过程。Knative Serving 组件允许部署无服务器应用程序和函数。这使得可以向容器提供流量，并根据请求的数量进行自动缩放。该服务组件还负责在对代码和配置进行更改时进行快照。Knative Eventing 组件帮助我们构建事件驱动的应用程序。该组件允许应用程序为事件流产生事件，并从事件流中消费事件。

以下图示了 Knative 框架及其依赖项以及每个组件的利益相关者：

![图 6.1：Knative 依赖项和利益相关者](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_06_01.jpg)

###### 图 6.1：Knative 依赖项和利益相关者

底层代表了 Kubernetes 框架，它作为 Knative 框架的容器编排层使用。Kubernetes 可以部署在任何基础设施上，例如 Google Cloud Platform 或本地系统。接下来，我们有**Istio**服务网格层，它管理集群内的网络路由。这一层提供了许多好处，包括流量管理、可观察性和安全性。在顶层，Knative 在**Istio**上运行在 Kubernetes 集群上。在 Knative 层，一端我们可以看到通过 GitHub 项目向 Knative 框架贡献代码的贡献者，另一端我们可以看到构建和部署应用程序在 Knative 框架之上的应用程序开发人员。

#### 注意

有关 Istio 的更多信息，请参阅[`istio.io/`](https://istio.io/)。

现在我们对 Knative 有了这样的理解，让我们在下一节中看看如何在 Kubernetes 集群上安装 Knative。

### 在 GKE 上开始使用 Knative

在本节中，我们将带您完成在 Kubernetes 集群上安装 Knative 的过程。我们将使用 Google Kubernetes Engine（GKE）来设置一个 Kubernetes 集群。GKE 是 Google 云中的托管 Kubernetes 集群服务。它允许我们在不安装、管理和操作自己的集群的负担下运行 Kubernetes 集群。

我们需要安装和配置以下先决条件才能继续本节：

+   一个 Google Cloud 账户

+   gcloud CLI

+   kubectl CLI（v1.10 或更新版本）

首先，我们需要设置一些环境变量，这些变量将与**gcloud** CLI 一起使用。您应该使用您的 GCP 项目的名称更新`<your-gcp-project-name>`。我们将使用`us-central1-a`作为 GCP 区域。在您的终端窗口中执行以下命令以设置所需的环境变量：

```
$ export GCP_PROJECT=<your-gcp-project-name>
$ export GCP_ZONE=us-central1-a
$ export GKE_CLUSTER=knative-cluster
```

输出应该如下：

![图 6.2：设置环境变量](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_06_02.jpg)

###### 图 6.2：设置环境变量

将我们的 GCP 项目设置为`gcloud` CLI 命令要使用的默认项目：

```
$ gcloud config set core/project $GCP_PROJECT
```

输出应该如下：

![图 6.3：设置默认的 GCP 项目](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_06_03.jpg)

###### 图 6.3：设置默认的 GCP 项目

现在我们可以使用`gcloud`命令创建 GKE 集群。Knative 需要一个版本为 1.11 或更新的 Kubernetes 集群。我们将使用 GKE 提供的**Istio**插件来为这个集群提供支持。以下是运行 Knative 组件所需的 Kubernetes 集群的推荐配置：

+   Kubernetes 版本 1.11 或更新

+   具有四个 vCPU（n1-standard-4）的 Kubernetes 节点

+   启用最多 10 个节点的节点自动缩放

+   `cloud-platform`的 API 范围

执行以下命令来创建一个符合这些要求的 GKE 集群：

```
     $ gcloud beta container clusters create $GKE_CLUSTER \
    --zone=$GCP_ZONE \
    --machine-type=n1-standard-4 \
    --cluster-version=latest \
    --addons=HorizontalPodAutoscaling,HttpLoadBalancing,Istio \
    --enable-stackdriver-kubernetes \
    --enable-ip-alias \
    --enable-autoscaling --min-nodes=1 --max-nodes=10 \
    --enable-autorepair \
    --scopes cloud-platform
```

输出应该如下：

![图 6.4：创建一个 GKE 集群](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_06_04.jpg)

###### 图 6.4：创建一个 GKE 集群

设置 Kubernetes 集群可能需要几分钟的时间。一旦集群准备好，我们将使用命令`gcloud container clusters get-credentials`来获取新集群的凭据，并配置**kubectl** CLI，如下面的代码片段所示：

```
$ gcloud container clusters get-credentials $GKE_CLUSTER --zone $GCP_ZONE --project $GCP_PROJECT
```

输出应该如下：

![图 6.5：获取 GKE 集群的凭据](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_06_05.jpg)

###### 图 6.5：获取 GKE 集群的凭据

现在您已成功创建了带有**Istio**的 GKE 集群，并配置了`kubectl`以访问新创建的集群。我们现在可以继续进行下一步，安装 Knative。我们将安装 Knative 版本 0.8，这是撰写本书时可用的最新版本。

我们将使用`kubectl` CLI 将 Knative 组件应用到 Kubernetes 集群上。首先，运行`kubectl apply`命令，并使用`-l knative.dev/crd-install=true`标志来防止安装过程中的竞争条件：

```
$ kubectl apply --selector knative.dev/crd-install=true \
   -f https://github.com/knative/serving/releases/download/v0.8.0/serving.yaml \
   -f https://github.com/knative/eventing/releases/download/v0.8.0/release.yaml \
   -f https://github.com/knative/serving/releases/download/v0.8.0/monitoring.yaml
```

接下来，再次运行命令，不带`-l knative.dev/crd-install=true`标志来完成安装：

```
$ kubectl apply -f https://github.com/knative/serving/releases/download/v0.8.0/serving.yaml \
   -f https://github.com/knative/eventing/releases/download/v0.8.0/release.yaml \
   -f https://github.com/knative/serving/releases/download/v0.8.0/monitoring.yaml
```

一旦命令完成，执行以下命令来检查安装的状态。确保所有的 pod 都有**Running**的状态：

```
$ kubectl get pods --namespace knative-serving
$ kubectl get pods --namespace knative-eventing
$ kubectl get pods --namespace knative-monitoring
```

输出应该如下：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_06_06.jpg)

###### 图 6.6：验证 Knative 安装

在这个阶段，您已经在 GKE 上设置了一个 Kubernetes 集群并安装了 Knative。现在我们准备在 Knative 上部署我们的第一个应用程序。

### 练习 16：在 Knative 上部署一个示例应用程序

在前面的部分中，我们成功在 Kubernetes 和**Istio**之上部署了 Knative。在这个练习中，我们将在 Knative 框架上部署我们的第一个应用程序。为了进行这次部署，我们将使用一个用 Node.js 编写的示例 Web 应用程序。这个应用程序的 Docker 镜像可以在 Google 容器注册表中找到，地址为`gcr.io/knative-samples/helloworld-nodejs`。这些步骤可以适应部署我们自己的 Docker 镜像到 Docker Hub 或任何其他容器注册表。

这个示例的“hello world”应用程序将读取一个名为`TARGET`的环境变量，并打印`Hello <VALUE_OF_TARGET>!`作为输出。如果未为`TARGET`环境变量定义值，则它将打印`NOT SPECIFIED`作为输出。

让我们首先创建应用程序的服务定义文件。这个文件定义了与应用程序相关的信息，包括应用程序名称和应用程序 Docker 镜像：

#### 注意

Knative 服务对象和 Kubernetes 服务对象是两种不同的类型。

1.  创建一个名为`hello-world.yaml`的文件，其中包含以下内容。这个 Knative 服务对象定义了部署此服务的命名空间、用于容器的 Docker 镜像以及任何环境变量等数值：

```
          apiVersion: serving.knative.dev/v1alpha1 
kind: Service
metadata:
  name: helloworld-nodejs 
  namespace: default 
spec:
  runLatest:
    configuration:
      revisionTemplate:
        spec:
          container:
            image: gcr.io/knative-samples/helloworld-nodejs 
            env:
              - name: TARGET 
                value: "Knative NodeJS App"
```

1.  一旦`hello-world.yaml`文件准备好，我们可以使用`kubectl apply`命令部署我们的应用程序：

```
$ kubectl apply -f hello-world.yaml
```

输出应该如下所示：

![图 6.7：部署 helloworld-nodejs 应用程序](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_06_07.jpg)

###### 图 6.7：部署 helloworld-nodejs 应用程序

1.  上一个命令将创建多个对象，包括 Knative 服务、配置、修订、路由和 Kubernetes 部署。我们可以通过列出新创建的对象来验证应用程序，就像以下命令一样：

```
$ kubectl get ksvc
$ kubectl get configuration
$ kubectl get revision
$ kubectl get route
$ kubectl get deployments
```

输出应该如下所示：

![图 6.8：验证 helloworld-nodejs 应用程序部署](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_06_08.jpg)

###### 图 6.8：验证 helloworld-nodejs 应用程序部署

1.  一旦我们的应用程序成功部署，我们可以使用 HTTP 请求调用这个应用程序。为此，我们需要确定 Kubernetes 集群的外部 IP 地址。执行以下命令将`EXTERNAL-IP`的值导出到名为`EXTERNAL_IP`的环境变量中：

```
$ export EXTERNAL_IP=$(kubectl get svc istio-ingressgateway --namespace istio-system --output 'jsonpath={.status.loadBalancer.ingress[0].ip}')
```

输出应该如下所示：

![图 6.9：导出 istio-ingressgateway 服务的外部 IP](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_06_09.jpg)

###### 图 6.9：导出 istio-ingressgateway 服务的外部 IP

接下来，我们需要找到`helloworld-nodejs`应用程序的主机 URL。执行以下命令并注意**URL**列的值。此 URL 采用以下形式：`http://<application-name>.<namespace>.example.com:`

```
$ kubectl get route helloworld-nodejs
```

输出应该如下所示：

![图 6.10：列出 helloworld-nodejs 路由](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_06_10.jpg)

###### 图 6.10：列出 helloworld-nodejs 路由

1.  现在我们可以使用我们在之前步骤中记录的`EXTERNAL_IP`和`URL`值来调用我们的应用程序。让我们使用以下命令进行`curl`请求：

```
$ curl -H "Host: helloworld-nodejs.default.example.com" http://${EXTERNAL_IP}
```

输出应该如下所示：

![图 6.11：调用 helloworld-nodejs 应用程序](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_06_11.jpg)

###### 图 6.11：调用 helloworld-nodejs 应用程序

您应该收到预期的输出为**Hello Knative NodeJS App!**。这表明我们已成功在 Knative 平台上部署和调用了我们的第一个应用程序。

## Knative 服务组件

在前一节中，我们使用服务类型的 YAML 文件部署了我们的第一个 Knative 应用程序。在部署服务时，它创建了多个其他对象，包括配置、修订和路由对象。在本节中，让我们讨论每个这些对象：

Knative 服务组件中有四种资源类型：

+   **配置**：定义应用程序的期望状态

+   **修订**：只读快照，跟踪配置的更改

+   **路由**：提供到修订的流量路由

+   **服务**：路由和配置的顶层容器

以下图示说明了每个这些组件之间的关系：

![图 6.12：Knative 服务、路由、配置和修订之间的关系](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_06_12.jpg)

###### 图 6.12：Knative 服务、路由、配置和修订之间的关系

**配置**用于定义应用程序的期望状态。这将定义用于应用程序的容器映像和任何其他所需的配置参数。每次更新**配置**时都会创建一个新的**修订版**。**修订版**指的是代码和**配置**的快照。这用于记录**配置**更改的历史。**路由**用于定义应用程序的流量路由策略，并为应用程序提供 HTTP 端点。默认情况下，**路由**将流量发送到**配置**创建的最新**修订版**。**路由**还可以配置更高级的场景，包括将流量发送到特定的**修订版**或根据定义的百分比将流量分配到不同的修订版。**服务**对象用于管理应用程序的整个生命周期。在部署新应用程序时，需要手动创建**配置**和**路由**对象，但**服务**可以通过自动创建和管理**配置**和**路由**对象来简化这一过程。

在接下来的部分，我们将使用金丝雀部署来部署 Knative 应用程序。让我们首先了解一下金丝雀部署到底是什么。

### 金丝雀部署

金丝雀部署是一种部署策略，用于在生产环境中推出新版本的代码。这是一种安全的部署新版本代码到生产环境并将一小部分流量切换到新版本的过程。这样，开发和部署团队可以在对生产流量影响最小的情况下验证新版本的代码。一旦验证完成，所有流量将切换到新版本。除了金丝雀部署之外，还有几种其他部署类型，例如大爆炸部署、滚动部署和蓝绿部署。

在我们在*练习 16*中部署的`helloworld-nodejs`应用程序中，我们使用了带有`spec.runLatest`字段的服务对象，该字段将所有流量定向到最新可用的修订版。在接下来的练习中，我们将使用单独的配置和路由对象，而不是服务对象。

#### 注意：

有关金丝雀部署技术的更多信息，请参阅[`dev.to/mostlyjason/intro-to-deployment-strategies-blue-green-canary-and-more-3a3`](https://dev.to/mostlyjason/intro-to-deployment-strategies-blue-green-canary-and-more-3a3)。

### 练习 17：Knative 的金丝雀部署

在这个练习中，我们将实施金丝雀部署策略来部署 Knative 应用程序。首先，我们将部署应用程序的初始版本（版本 1），并将 100%的流量路由到该版本。接下来，我们将创建应用程序的第 2 个版本，并将 50%的流量路由到版本 1，剩下的 50%路由到版本 2。最后，我们将更新路由，将 100%的流量发送到版本 2。

以下步骤将帮助您完成练习：

1.  首先，从创建应用程序的初始版本（`v1`）开始。创建一个名为`canary-deployment.yaml`的文件，内容如下。这个应用程序使用与我们之前使用的相同的 Docker 镜像（`gcr.io/knative-samples/helloworld-nodejs`），并将`TARGET`环境变量设置为`This is the first version - v1`：

```
apiVersion: serving.knative.dev/v1alpha1
kind: Configuration
metadata:
  name: canary-deployment
  namespace: default
spec:
  template:
    spec:
      containers:
        - image: gcr.io/knative-samples/helloworld-nodejs
          env:
            - name: TARGET
              value: "This is the first version - v1"
```

1.  使用在上一步中创建的 YAML 文件，使用`kubectl apply`命令部署应用程序的第一个版本：

```
$ kubectl apply -f canary-deployment.yaml
```

输出应该如下所示：

![图 6.13：创建金丝雀部署](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_06_13.jpg)

###### 图 6.13：创建金丝雀部署

1.  让我们获取此配置创建的修订名称，因为我们在下一步中需要这个值。执行`kubectl get configurations`命令，并检索`latestCreatedRevisionName`字段的值：

```
$ kubectl get configurations canary-deployment -o=jsonpath='{.status.latestCreatedRevisionName}'
```

输出应该如下所示：

![图 6.14：获取金丝雀部署配置的最新修订版本](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_06_14.jpg)

###### 图 6.14：获取金丝雀部署配置的最新修订版本

对我来说，从前面的命令返回的值是`canary-deployment-xgvl8`。请注意，你的值将会不同。

1.  接下来的步骤是创建路由对象。让我们创建一个名为`canary-deployment-route.yaml`的文件，内容如下（请记得用你在上一步中记录的修订名称替换`canary-deployment-xgvl8`）。在`spec.traffic`部分下，你可以看到 100%的流量被路由到我们之前创建的修订版本：

```
apiVersion: serving.knative.dev/v1alpha1
kind: Route
metadata:
  name: canary-deployment
  namespace: default 
spec:
  traffic:
    - revisionName: canary-deployment-xgvl8
      percent: 100 
```

1.  使用`kubectl apply`命令创建路由对象：

```
$ kubectl apply -f canary-deployment-route.yaml
```

输出应该如下所示：

![图 6.15：创建金丝雀部署路由](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_06_15.jpg)

###### 图 6.15：创建 canary-deployment 路由

1.  对应用程序发出请求，并观察`Hello This is the first version - v1!`的预期输出：

```
$ curl -H "Host: canary-deployment.default.example.com" "http://${EXTERNAL_IP}"
```

输出应如下所示：

![图 6.16：调用 canary-deployment](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_06_16.jpg)

###### 图 6.16：调用 canary-deployment

1.  一旦应用程序成功调用，我们可以部署应用程序的第 2 个版本。使用以下内容更新`canary-deployment.yaml`。在应用程序的第 2 个版本中，我们只需要将`TARGET`环境变量的值从`This is the first version - v1`更新为`This is the second version - v2`：

```
apiVersion: serving.knative.dev/v1alpha1
kind: Configuration
metadata:
  name: canary-deployment
  namespace: default
spec:
  template:
    spec:
      containers:
        - image: gcr.io/knative-samples/helloworld-nodejs
          env:
            - name: TARGET
              value: "This is the second version - v2"
```

1.  使用`kubectl apply`应用更新的配置：

```
$ kubectl apply -f canary-deployment.yaml
```

输出应如下所示：

![图 6.17：将 canary-deployment 更新为版本 2](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_06_17.jpg)

###### 图 6.17：将 canary-deployment 更新为版本 2

1.  现在我们可以使用`kubectl get revisions`命令检查创建的修订版本，同时更新配置：

```
$ kubectl get revisions
```

输出应如下所示：

![图 6.18：获取 canary-deployment 的修订版本](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_06_18.jpg)

###### 图 6.18：获取 canary-deployment 的修订版本

1.  让我们获取由`canary-deployment`配置创建的最新修订版本：

```
$ kubectl get configurations canary-deployment -o=jsonpath='{.status.latestCreatedRevisionName}'
```

输出应如下所示：

![图 6.19：获取 canary-deployment 配置的最新修订版本](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_06_19.jpg)

###### 图 6.19：获取 canary-deployment 配置的最新修订版本

1.  现在是时候向我们应用程序的新版本发送一些流量了。更新`canary-deployment-route.yaml`的`spec.traffic`部分，将 50%的流量发送到旧修订版本，50%发送到新修订版本：

```
apiVersion: serving.knative.dev/v1alpha1
kind: Route
metadata:
  name: canary-deployment
  namespace: default 
spec:
  traffic:
    - revisionName: canary-deployment-xgvl8
      percent: 50 
    - revisionName: canary-deployment-8pp4s
      percent: 50 
```

1.  使用以下命令对路由进行更改：

```
$ kubectl apply -f canary-deployment-route.yaml
```

输出应如下所示：

![图 6.20：更新 canary-deployment 路由](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_06_20.jpg)

###### 图 6.20：更新 canary-deployment 路由

1.  现在我们可以多次调用应用程序，观察流量如何在两个修订版本之间分配：

```
$ curl -H "Host: canary-deployment.default.example.com" "http://${EXTERNAL_IP}" 
```

1.  一旦我们成功验证了应用程序的第 2 个版本，我们可以将`canary-deployment-route.yaml`更新为将 100%的流量路由到最新的修订版本：

```
apiVersion: serving.knative.dev/v1alpha1
kind: Route
metadata:
  name: canary-deployment
  namespace: default 
spec:
  traffic:
    - revisionName: canary-deployment-xgvl8
      percent: 0 
    - revisionName: canary-deployment-8pp4s
      percent: 100 
```

1.  使用以下命令对路由进行更改：

```
$ kubectl apply -f canary-deployment-route.yaml
```

输出应如下所示：

![图 6.21：更新 canary-deployment 路由](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_06_21.jpg)

###### 图 6.21：更新 canary-deployment 路由

1.  现在多次调用应用程序，以验证所有流量都流向应用程序的第 2 个版本：

```
$ curl -H "Host: blue-green-deployment.default.example.com" "http://${EXTERNAL_IP}" 
```

在这个练习中，我们成功地使用配置和路由对象来执行 Knative 的金丝雀部署。

## Knative 监控

Knative 预先安装了 Grafana，这是一个开源的度量分析和可视化工具。Grafana pod 可在`knative-monitoring`命名空间中找到，并且可以使用以下命令列出：

```
$ kubectl get pods -l app=grafana -n knative-monitoring
```

输出应该如下所示：

![图 6.22：列出 Grafana pod](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_06_22.jpg)

###### 图 6.22：列出 Grafana pod

我们可以使用`kubectl port-forward`命令暴露 Grafana UI，该命令将本地端口`3000`转发到 Grafana pod 的端口`3000`。打开一个新的终端并执行以下命令：

```
$ kubectl port-forward $(kubectl get pod -n knative-monitoring -l app=grafana -o jsonpath='{.items[0].metadata.name}') -n knative-monitoring 3000:3000
```

输出应该如下所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_06_23.jpg)

###### 图 6.23：将端口转发到 Grafana pod

现在我们可以从我们的网络浏览器上的`http://127.0.0.1:3000`导航到 Grafana UI。

输出应该如下所示：

![图 6.24：Grafana UI](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_06_24.jpg)

###### 图 6.24：Grafana UI

Knative 的 Grafana 仪表板带有多个仪表板，包括以下内容：

![图 6.25：仪表板](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_06_25.jpg)

###### 图 6.25：仪表板

## Knative 自动缩放器

Knative 具有内置的自动缩放功能，根据接收到的 HTTP 请求的数量自动调整应用程序 pod 的数量。当需求增加时，它将增加 pod 数量，当需求减少时，它将减少 pod 数量。当 pod 处于空闲状态且没有传入请求时，pod 数量将缩减为零。

Knative 使用两个组件，自动缩放器和激活器，来实现前面提到的功能。这些组件部署为`knative-serving`命名空间中的 pod，如下面的代码片段所示：

```
NAME                          READY   STATUS    RESTARTS   AGE
activator-7c8b59d78-9kgk5     2/2     Running   0          15h
autoscaler-666c9bfcc6-vwrj6   2/2     Running   0          15h
controller-799cd5c6dc-p47qn   1/1     Running   0          15h
webhook-5b66fdf6b9-cbllh      1/1     Running   0          15h
```

激活器组件负责收集有关修订版的并发请求数量的信息，并将这些值报告给自动缩放器。自动缩放器组件将根据激活器报告的指标增加或减少 pod 的数量。默认情况下，自动缩放器将尝试通过扩展或缩减 pod 来维持每个 pod 的 100 个并发请求。所有 Knative 与自动缩放器相关的配置都存储在`knative-serving`命名空间中名为`config-autoscaler`的配置映射中。Knative 还可以配置为使用 Kubernetes 提供的**水平 Pod 自动缩放器**（**HPA**），HPA 将根据 CPU 使用情况自动调整 pod 的数量。

### 练习 18：使用 Knative 进行自动缩放

在这个练习中，我们将通过部署一个示例应用程序来执行 Knative pod 自动缩放：

1.  创建一个名为`autoscale-app.yaml`的服务定义文件，内容如下。该文件定义了一个名为`autoscale-app`的服务，该服务将使用`gcr.io/knative-samples/autoscale-go:0.1`示例 Docker 镜像。`autoscaling.knative.dev/target`用于配置每个 pod 的目标并发请求数量：

```
apiVersion: serving.knative.dev/v1alpha1
kind: Service
metadata:
  name: autoscale-app
spec:
  runLatest:
    configuration:
      revisionTemplate:
        metadata:
          annotations:
            autoscaling.knative.dev/target: "10"
        spec:
          container:
            image: "gcr.io/knative-samples/autoscale-go:0.1"
```

1.  使用`kubectl apply`命令应用服务定义：

```
$ kubectl apply -f autoscale-app.yaml
```

输出应如下所示：

![图 6.26：创建 autoscale-app](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_06_26.jpg)

###### 图 6.26：创建 autoscale-app

1.  一旦应用程序准备就绪，我们可以生成一个负载到**autoscale-app**应用程序以观察自动缩放。为此，我们将使用一个名为`hey`的负载生成器。使用以下`curl`命令下载`hey`二进制文件。

```
$ curl -Lo hey https://storage.googleapis.com/hey-release/hey_linux_amd64
```

输出应如下所示：

![图 6.27：安装 hey](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_06_27.jpg)

###### 图 6.27：安装 hey

1.  为`hey`二进制文件添加执行权限，并将其移动到`/usr/local/bin/`路径中：

```
$ chmod +x hey
$ sudo mv hey /usr/local/bin/
```

输出应如下所示：

![图 6.28：将 hey 移动到/usr/local/bin](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_06_28.jpg)

###### 图 6.28：将 hey 移动到/usr/local/bin

1.  现在我们准备使用`hey`工具生成负载。`hey`工具在生成负载时支持多个选项。对于这种情况，我们将使用并发数为 50（使用`-c`标志）持续 60 秒（使用`-z`标志）的负载：

```
$ hey -z 60s -c 50 \
   -host "autoscale-app.default.example.com" \
   "http://${EXTERNAL_IP?}?sleep=1000" 
```

1.  在单独的终端中，观察负载期间创建的 pod 数量：

```
$ kubectl get pods --watch
```

您将看到类似以下的输出：

```
     NAME                                             READY   STATUS    RESTARTS   AGE
autoscale-app-7jt29-deployment-9c9c4b474-4ttl2   3/3     Running   0          58s
autoscale-app-7jt29-deployment-9c9c4b474-6pmjs   3/3     Running   0          60s
autoscale-app-7jt29-deployment-9c9c4b474-7j52p   3/3     Running   0          63s
autoscale-app-7jt29-deployment-9c9c4b474-dvcs6   3/3     Running   0          56s
autoscale-app-7jt29-deployment-9c9c4b474-hmkzf   3/3     Running   0          62s
```

1.  打开 Grafana 中的**Knative Serving - Scaling Debugging**仪表板，观察自动缩放如何在负载期间增加了 pod 数量，并在负载停止后将 pod 数量减少到零，如下面的截图所示：

![图 6.29：修订 pod 计数指标](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_06_29.jpg)

###### 图 6.29：修订 pod 计数指标

![图 6.30：观察并发度指标](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_06_30.jpg)

###### 图 6.30：观察并发度指标

我们已成功配置了 Knative 的自动缩放器，并通过 Grafana 仪表板观察到了自动缩放。

### Google Cloud Run

在前面的部分中，我们讨论了 Knative。我们学习了如何在 Kubernetes 集群上安装 Istio 和 Knative，以及如何使用 Knative 运行 Docker 镜像。但是 Knative 平台的优势伴随着管理底层 Kubernetes 集群和 Istio 的运营开销。来自 Google Cloud 的托管 Kubernetes 服务 GKE 将帮助我们管理 Kubernetes 主控组件，但是我们仍然必须自己管理所有的 Kubernetes 节点。

为了将开发人员的所有基础设施管理任务抽象出来，Google 推出了一个名为 Cloud Run 的新服务。这是一个完全托管的平台，建立在 Knative 项目之上，用于运行无状态的 HTTP 驱动容器。Cloud Run 提供与 Knative 相同的功能集，包括自动缩放、零缩放、版本控制和事件。Cloud Run 在 Google Cloud Next '19 大会上作为 Google Cloud 无服务器计算堆栈的最新成员推出。在撰写本书时，Cloud Run 服务仍处于测试阶段，仅在有限数量的地区提供。

现在让我们进行一个练习，在 Google Cloud Run 上部署容器。

### 练习 19：在 Google Cloud Run 上部署容器

在这个练习中，我们将在 Google Cloud Run 平台上部署一个预构建的 Docker 镜像。

以下步骤将帮助您完成练习：

1.  从浏览器导航到您的 GCP 控制台，并从菜单中选择**Cloud Run**（在**计算**类别中），如下图所示：![图 6.31：Cloud Run 的 GCP 菜单](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_06_31.jpg)

###### 图 6.31：Cloud Run 的 GCP 菜单

1.  单击**创建服务**按钮以创建新服务。

1.  使用以下值填写创建服务表单：

容器镜像 URL：[gcr.io/knative-samples/helloworld-nodejs](http://gcr.io/knative-samples/helloworld-nodejs)

部署平台：**Cloud Run**（完全托管）

位置：从选项中选择任何您喜欢的地区

服务名称：**hello-world**

身份验证：**允许未经身份验证的调用**

![图 6.32：Cloud Run 创建服务表单](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_06_32.jpg)

###### 图 6.32：Cloud Run 创建服务表单

1.  单击**创建**按钮。

1.  现在我们将被重定向到部署的服务页面，其中包括关于新部署的**hello-world**服务的详细信息。我们可以看到已创建一个名为**hello-world-00001**的修订版本，如下图所示：![图 6.33：服务详细信息页面](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_06_33.jpg)

###### 图 6.33：服务详细信息页面

1.  点击显示的 URL 链接来运行容器。请注意，每个新实例的 URL 都会有所不同：![图 6.34：调用 hello-world 应用程序](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_06_34.jpg)

###### 图 6.34：调用 hello-world 应用程序

1.  接下来，我们将通过更新**TARGET**环境变量来部署应用程序的新修订版。返回**GCP**控制台，点击**部署新修订版**按钮。

1.  从**部署修订版到 hello-world（us-central1）**表单中，点击**显示可选修订设置**链接，这将指向我们到附加设置部分：![图 6.35：可选修订设置](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_06_35.jpg)

###### 图 6.35：可选修订设置

1.  在环境变量部分，创建一个名为`TARGET`的新环境变量，值为`Cloud Run Deployment`：![图 6.36：设置 TARGET 环境变量](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_06_36.jpg)

###### 图 6.36：设置 TARGET 环境变量

1.  点击**部署**按钮。

1.  现在我们可以看到**hello-world**应用程序的新修订版名为`hello-world-00002`，100%的流量被路由到最新的修订版：![图 6.37：hello-world 应用程序的新修订版](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_06_37.jpg)

###### 图 6.37：hello-world 应用程序的新修订版

1.  再次点击 URL 来运行更新的修订版：

![图 6.38：调用 hello-world 应用程序](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_06_38.jpg)

###### 图 6.38：调用 hello-world 应用程序

我们已成功在 Google Cloud Run 平台上部署了预构建的 Docker 镜像。

## 介绍 Virtual Kubelet

Virtual Kubelet 是 Kubernetes kubelet 的开源实现，充当 kubelet。这是来自**Cloud Native Computing Foundation**（**CNCF**）的沙箱项目，Virtual Kubelet 的第一个主要版本（v 1.0）于 2019 年 7 月 8 日发布。

在进一步深入 Virtual Kubelet 之前，让我们回顾一下 Kubernetes 架构中的 kubelet 是什么。kubelet 是在 Kubernetes 集群中每个节点上运行的代理，负责管理节点内的 pod。kubelet 从 Kubernetes API 接收指令，以识别要在节点上调度的 pod，并与节点的底层容器运行时（例如 Docker）交互，以确保所需数量的 pod 正在运行并且它们是健康的。

除了管理 pod 外，kubelet 还执行几项其他任务：

+   更新 Kubernetes API 与 pod 的当前状态

+   监控和报告节点的健康指标，如 CPU、内存和磁盘利用率，到 Kubernetes 主节点

+   从 Docker 注册表中拉取分配的 pod 的 Docker 镜像

+   为 pod 创建和挂载卷

+   为 API 服务器提供一个接口，以执行诸如`kubectl logs`、`kubectl exec`和`kubectl attach`等命令，用于 pod

以下图显示了一个具有标准和虚拟 kubelet 的 Kubernetes 集群：

![图 6.39：具有标准 kubelet 和虚拟 kubelet 的 Kubernetes 集群](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_06_39.jpg)

###### 图 6.39：具有标准 kubelet 和虚拟 kubelet 的 Kubernetes 集群

从 Kubernetes API 的视角来看，Virtual Kubelet 将会像传统的 kubelet 一样。它将在现有的 Kubernetes 集群中运行，并在 Kubernetes API 中注册自己为一个节点。Virtual Kubelet 将以与 kubelet 相同的方式运行和管理 pod。但与在节点内运行 pod 的 kubelet 相反，Virtual Kubelet 将利用外部服务来运行 pod。这将把 Kubernetes 集群连接到其他服务，如无服务器容器平台。Virtual Kubelet 支持越来越多的提供者，包括以下：

+   阿里巴巴云弹性容器实例（ECI）

+   AWS Fargate

+   Azure Batch

+   Azure 容器实例（ACI）

+   Kubernetes 容器运行时接口（CRI）

+   华为云容器实例（CCI）

+   HashiCorp Nomad

+   OpenStack Zun

在这些平台上运行 pod 带来了无服务器世界的好处。我们不必担心基础架构，因为它由云提供商管理。Pod 将根据收到的请求数量自动扩展和缩减。此外，我们只需为使用的资源付费。

### 练习 20：在 AKS 上部署 Virtual Kubelet

在这个练习中，我们将在 Azure Kubernetes Service（AKS）上配置 Virtual Kubelet，并使用 ACI 提供程序。在这个练习中，我们将使用 Azure 中提供的以下服务。

+   AKS：AKS 是 Azure 上的托管 Kubernetes 服务。

+   ACI：ACI 提供了在 Azure 上运行容器的托管服务。

+   Azure Cloud Shell：一个交互式的基于浏览器的 shell，支持 Bash 和 PowerShell。

您需要具备以下先决条件才能进行这个练习：

+   Microsoft Azure 账户

+   Azure CLI

+   kubectl CLI

+   Helm

我们将使用 Azure Cloud Shell，其中预先安装了所有先前提到的 CLI：

1.  转到[`shell.azure.com/`](https://shell.azure.com/)在浏览器窗口中打开 Cloud Shell。从“欢迎使用 Azure Cloud Shell”窗口中选择**Bash**：![图 6.40：欢迎使用 Azure Cloud Shell 窗口](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_06_40.jpg)

###### 图 6.40：欢迎使用 Azure Cloud Shell 窗口

1.  单击“创建存储”按钮以为 Cloud Shell 创建存储账户。请注意，这是一个一次性任务，仅在我们第一次使用 Cloud Shell 时需要执行：![图 6.41：为 Cloud Shell 挂载存储](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_06_41.jpg)

###### 图 6.41：为 Cloud Shell 挂载存储

Cloud Shell 窗口将如下所示：

![图 6.42：Cloud Shell 窗口](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_06_42.jpg)

###### 图 6.42：Cloud Shell 窗口

1.  一旦 Cloud Shell 准备就绪，我们就可以开始创建 AKS 集群。

首先，我们需要创建一个 Azure 资源组，以便逻辑上将相关的 Azure 资源分组。执行以下命令，在 West US（`westus`）地区创建一个名为`serverless-kubernetes-group`的资源组：

```
$ az group create --name serverless-kubernetes-group --location westus
```

输出应该如下所示：

![图 6.43：创建 Azure 资源组](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_06_43.jpg)

###### 图 6.43：创建 Azure 资源组

1.  注册您的订阅以使用`Microsoft.Network`命名空间：

```
$ az provider register --namespace Microsoft.Networks
```

输出应该如下所示：

![图 6.44：注册订阅](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_06_44.jpg)

###### 图 6.44：注册订阅

1.  接下来，我们将创建一个 Azure Kubernetes 集群。以下命令将创建一个名为`virtual-kubelet-cluster`的 AKS 集群，其中包含一个节点。此命令将需要几分钟来执行：

```
$ az aks create --resource-group serverless-kubernetes-group --name virtual-kubelet-cluster --node-count 1 --node-vm-size Standard_D2 --network-plugin azure --generate-ssh-keys
```

AKS 集群创建成功后，上述命令将返回一些 JSON 输出，其中包含集群的详细信息：

![图 6.45：创建 AKS 集群](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_06_45.jpg)

###### 图 6.45：创建 AKS 集群

1.  接下来，我们需要配置 kubectl CLI 以与新创建的 AKS 集群通信。执行`az aks get-credentials`命令来下载凭据并配置 kubectl CLI 以与`virtual-kubelet-cluster`集群一起工作的命令如下：

#### 注意

我们不需要安装 kubectl CLI，因为 Cloud Shell 已经预装了 kubectl。

```
$ az aks get-credentials --resource-group serverless-kubernetes-group --name virtual-kubelet-cluster
```

输出应该如下所示：

![图 6.46：配置 kubectl](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_06_46.jpg)

###### 图 6.46：配置 kubectl

1.  现在我们可以通过执行 `kubectl get nodes` 命令来验证从 Cloud Shell 到集群的连接，该命令将列出 AKS 集群中可用的节点：

```
$ kubectl get nodes
```

输出应如下所示：

![图 6.47：列出 Kubernetes 节点](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_06_47.jpg)

###### 图 6.47：列出 Kubernetes 节点

1.  如果这是您第一次使用 ACI 服务，您需要在订阅中注册 `Microsoft.ContainerInstance` 提供程序。我们可以使用以下命令检查 `Microsoft.ContainerInstance` 提供程序的注册状态：

```
$ az provider list --query "[?contains(namespace,'Microsoft.ContainerInstance')]" -o table
```

输出应如下所示：

![图 6.48：检查 Microsoft.ContainerInstace 提供程序的注册状态](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_06_48.jpg)

###### 图 6.48：检查 Microsoft.ContainerInstace 提供程序的注册状态

1.  如果 **RegistrationStatus** 列包含值 **NotRegistered**，则执行 `az provider register` 命令来注册 `Microsoft.ContainerInstance` 提供程序。如果 **RegistrationStatus** 列包含值 **Registered**，则可以继续下一步：

```
$ az provider register --namespace Microsoft.ContainerInstance
```

输出应如下所示：

![图 6.49：注册 Microsoft.ContainerInstance 提供程序](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_06_49.jpg)

###### 图 6.49：注册 Microsoft.ContainerInstance 提供程序

1.  下一步是为 tiller 创建必要的 `ServiceAccount` 和 `ServiceAccount` 对象。创建一个名为 `tiller-rbac.yaml` 的文件，其中包含以下代码：

```
apiVersion: v1
kind: ServiceAccount
metadata:
  name: tiller
  namespace: kube-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: tiller
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
  - kind: ServiceAccount
    name: tiller
    namespace: kube-system
```

1.  然后执行 `kubectl apply` 命令来创建必要的 `ServiceAccount` 和 `ClusterRoleBinding` 对象：

```
$ kubectl apply -f tiller-rbac.yaml
```

输出应如下所示：

![图 6.50：创建 ServiceAccount 和 ClusterRoleBinding 对象](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_06_50.jpg)

###### 图 6.50：创建 ServiceAccount 和 ClusterRoleBinding 对象

1.  现在我们可以配置 Helm 使用我们在上一步中创建的 tiller 服务账户：

```
$ helm init --service-account tiller
```

输出应如下所示：

![图 6.51：配置 tiller](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_06_51.jpg)

###### 图 6.51：配置 tiller

1.  一旦所有配置都完成，我们可以使用 `az aks install-connector` 命令安装虚拟 Kubelet。我们将使用以下命令部署 Linux 和 Windows 连接器：

```
$ az aks install-connector \
    --resource-group serverless-kubernetes-group \
    --name virtual-kubelet-cluster \
    --connector-name virtual-kubelet \
    --os-type Both
```

输出应如下所示：

![图 6.52：安装虚拟 Kubelet](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_06_52.jpg)

###### 图 6.52：安装虚拟 Kubelet

1.  安装完成后，我们可以通过列出 Kubernetes 节点来验证它。将会有两个新节点，一个用于 Windows，一个用于 Linux：

```
$ kubectl get nodes
```

输出应如下所示：

![图 6.53：列出 Kubernetes 节点](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_06_53.jpg)

###### 图 6.53：列出 Kubernetes 节点

1.  现在我们已经在 AKS 集群中安装了 Virtual Kubelet。我们可以将一个应用程序部署到 Virtual Kubelet 引入的新节点上。我们将创建一个名为`hello-world`的 Kubernetes Deployment，使用`microsoft/aci-helloworld` Docker 镜像。

我们需要添加一个**nodeSelector**，将此 pod 专门分配给 Virtual Kubelet 节点。请注意，Virtual Kubelet 节点默认会被标记，以防止意外的 pod 在其上运行。我们需要为 pod 添加 tolerations，以允许它们被调度到这些节点上。

让我们创建一个名为`hello-world.yaml`的文件，内容如下：

```
     apiVersion: apps/v1
kind: Deployment
metadata:
  name: hello-world
spec:
  replicas: 1
  selector:
    matchLabels:
      app: hello-world
  template:
    metadata:
      labels:
        app: hello-world
    spec:
      containers:
      - name: hello-world
        image: microsoft/aci-helloworld
        ports:
        - containerPort: 80
      nodeSelector:
        kubernetes.io/role: agent
        type: virtual-kubelet
        beta.kubernetes.io/os: linux
      tolerations:
      - key: virtual-kubelet.io/provider
        operator: Equal
        value: azure
        effect: NoSchedule
```

1.  使用`kubectl apply`命令部署`hello-world`应用程序：

```
$ kubectl apply -f hello-world.yaml
```

输出应如下所示：

![图 6.54：创建 hello-world 部署](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_06_54.jpg)

###### 图 6.54：创建 hello-world 部署

1.  使用`kubectl get pods`命令和`-o wide`标志执行，以输出一个包含各个 pod 及其相应节点的列表。请注意，`hello-world-57f597bc59-q9w9k` pod 已被调度到`virtual-kubelet-virtual-kubelet-linux-westus`节点上：

```
$ kubectl get pods -o wide
```

输出应如下所示：

![图 6.55：使用-o wide 标志列出所有 pod](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_06_55.jpg)

###### 图 6.55：使用-o wide 标志列出所有 pod

因此，我们已成功在 AKS 上配置了带有 ACI 的 Virtual Kubelet，并在 Virtual Kubelet 节点上部署了一个 pod。

现在让我们完成一个活动，我们将在无服务器环境中部署一个容器化应用程序。

### 活动 6：在无服务器环境中部署容器化应用程序

假设你在一家初创公司工作，你的经理希望你创建一个可以根据给定时区返回当前日期和时间的应用程序。在初始阶段，预计该应用程序只会收到少量请求，但从长远来看将收到数百万个请求。该应用程序应能根据收到的请求数量自动扩展，无需进行任何修改。此外，你的经理不希望承担管理基础设施的负担，并希望该应用程序以尽可能低的成本运行。

执行以下步骤完成此活动：

1.  创建一个应用程序（使用任何你想要的语言），可以根据给定的`timezone`值提供当前日期和时间。

以下是用 PHP 编写的一些示例应用程序代码：

```
     <?php
if ( !isset ( $_GET['timezone'] ) ) {
    // Returns error if the timezone parameter is not provided
    $output_message = "Error: Timezone not provided"; 
} else if ( empty ( $_GET['timezone'] ) ) {
    // Returns error if the timezone parameter value is empty
    $output_message = "Error: Timezone cannot be empty"; 
} else {
    // Save the timezone parameter value to a variable
    $timezone = $_GET['timezone'];

    try {
        // Generates the current time for the provided timezone
        $date = new DateTime("now", new DateTimeZone($timezone) );
        $formatted_date_time = $date->format('Y-m-d H:i:s');
        $output_message = "Current date and time for $timezone is $formatted_date_time";
    } catch(Exception $e) {
        // Returns error if the timezone is invalid
        $output_message = "Error: Invalid timezone value"; 
    }
}
// Return the output message
echo $output_message;
```

1.  根据 Google Cloud Run 提供的指南对应用程序进行容器化。

以下是一个示例 Dockerfile 的内容：

```
# Use official PHP 7.3 image as base image
FROM php:7.3-apache
# Copy index.php file to the docker image
COPY index.php /var/www/html/
# Replace port 80 with the value from PORT environment variable in apache2 configuration files
RUN sed -i 's/80/${PORT}/g' /etc/apache2/sites-available/000-default.conf /etc/apache2/ports.conf
# Use the default production configuration file
RUN mv "$PHP_INI_DIR/php.ini-production" "$PHP_INI_DIR/php.ini"
```

1.  将 Docker 镜像推送到 Docker 注册表。

1.  使用 Cloud Run 运行应用程序。

输出应该如下所示：

![图 6.56：在无服务器环境中部署应用程序](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_06_56.jpg)

###### 图 6.56：在无服务器环境中部署应用程序

#### 注意

活动的解决方案可以在第 417 页找到。

## 摘要

在本章中，我们讨论了在 Kubernetes 上使用无服务器的优势。我们讨论了三种技术，它们在 Kubernetes 集群之上提供了无服务器的好处。这些技术是 Knative、Google Cloud Run 和 Virtual Kubelet。

首先，我们创建了一个带有 Istio 的 GKE 集群，并在其上部署了 Knative。然后我们学习了如何在 Knative 上部署应用程序。接下来，我们讨论了 Knative 的 serving 组件，以及如何使用配置和路由对象执行金丝雀部署。然后我们讨论了 Knative 上的监控，并观察了 Knative 根据收到的请求数进行自动扩展的工作原理。

我们还讨论了 Google Cloud Run，这是一个完全托管的平台，建立在 Knative 项目之上，用于运行无状态的 HTTP 驱动容器。然后我们学习了如何使用 Cloud Run 服务部署应用程序。

在最后一节中，我们学习了 Virtual Kubelet，这是 Kubernetes kubelet 的开源实现。我们了解了普通 kubelet 和 Virtual Kubelet 之间的区别。最后，我们在 AKS 集群上部署了 Virtual Kubelet，并将应用程序部署到了 Virtual Kubelet 节点。

在接下来的三章中，我们将专注于三种不同的 Kubernetes 无服务器框架，分别是 Kubeless、OpenWhisk 和 OpenFaaS。


# 第七章： 使用 Kubeless 的 Kubernetes 无服务器

## 学习目标

到本章结束时，您将能够：

+   使用 Minikube 创建 Kubernetes 集群

+   在 Kubernetes 上安装 Kubeless 框架

+   创建、更新、调用和删除 Kubeless 函数

+   列出、描述、调试和监视 Kubeless 函数

+   为 Kubeless 函数创建 HTTP 和 PubSub 触发器

在本章中，我们将首先了解 Kubeless 架构。然后，我们将创建我们的第一个 Kubeless 函数，部署它并调用它。您还将学习如何在 Kubeless 函数失败的情况下进行调试。

## Kubeless 简介

**Kubeless**是一个开源的、基于 Kubernetes 的无服务器框架，运行在 Kubernetes 之上。这使软件开发人员可以将代码部署到 Kubernetes 集群中，而不必担心底层基础设施。**Kubeless**是 Bitnami 的一个项目，Bitnami 是任何平台上打包应用程序的提供商。Bitnami 为超过 130 个应用程序提供软件安装程序，这使您可以快速高效地将这些软件应用程序部署到任何平台。

**Kubeless**函数支持多种编程语言，包括 Python、PHP、Ruby、Node.js、Golang、Java、.NET、Ballerina 和自定义运行时。这些函数可以通过 HTTP(S)调用以及使用 Kafka 或 NATS 消息系统的事件触发器来调用。Kubeless 还支持 Kinesis 触发器，将函数与 AWS Kinesis 服务关联起来，这是 AWS 提供的托管数据流服务。Kubeless 函数甚至可以使用定时触发器在指定的时间间隔内被调用。

Kubeless 配备了自己的命令行界面（CLI），名为`kubeless`，类似于 Kubernetes 提供的**kubectl** CLI。我们可以使用这个`kubeless` CLI 来创建、部署、列出和删除 Kubeless 函数。Kubeless 还有一个图形用户界面，使函数的管理更加容易。

在本章中，我们将使用 Kubeless 在 Kubernetes 上创建我们的第一个无服务器函数。然后，我们将使用多种机制调用此函数，包括 HTTP 和 PubSub 触发器。一旦我们熟悉了 Kubeless 的基础知识，我们将创建一个更高级的函数，可以向 Slack 发布消息。

### Kubeless 架构

Kubeless 框架是 Kubernetes 框架的扩展，利用了原生 Kubernetes 概念，如**自定义资源定义**（**CRDs**）和自定义控制器。由于 Kubeless 是建立在 Kubernetes 之上的，它可以利用 Kubernetes 中可用的所有出色功能，如自愈、自动扩展、负载平衡和服务发现。

#### 注意

自定义资源是 Kubernetes API 的扩展。您可以在官方 Kubernetes 文档中找到有关 Kubernetes 自定义资源的更多信息，网址为[`kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/`](https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/)。

让我们来看看 Kubernetes 架构，以了解其背后的核心概念：

![图 7.1：Kubeless 架构图](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_01.jpg)

###### 图 7.1：Kubeless 架构图

前面的图表类似于标准的 Kubernetes 架构，包括 Kubernetes 主节点和节点。可以有一个或多个负责集群整体决策的 Kubernetes 主节点。Kubernetes 节点用于托管 Kubernetes pod。这些 pod 包含软件开发人员编写的函数。函数的源代码将由控制器使用**ConfigMaps**注入到 pod 中。

这些 pod 将由**Kubeless 控制器**管理。在 Kubeless 框架安装过程中，它将启动一个集群内控制器，该控制器将持续监视函数资源。当部署函数时，该控制器将使用提供的运行时创建相关的服务、部署和 pod。

Kubeless 框架有三个核心概念：

+   功能

+   触发器

+   运行时

函数代表 Kubeless 框架执行的代码块。在安装过程中，将创建一个名为`functions.kubeless.io`的 CRD 来表示 Kubeless 函数。

触发器代表函数的调用机制。当接收到触发器时，Kubeless 函数将被调用。一个触发器可以关联一个或多个函数。在 Kubeless 上部署的函数可以使用五种可能的机制进行触发：

+   HTTP 触发器：这是通过基于 HTTP(S)的调用执行的，比如 HTTP GET 或 POST 请求。

+   CronJob 触发器：这是通过预定义的时间表执行的。

+   Kafka 触发器：当消息发布到 Kafka 主题时执行。

+   NATS 触发器：当消息发布到 NATS 主题时执行。

+   Kinesis 触发器：当记录发布到 AWS Kinesis 数据流时执行。

运行时代表可以用于编写和执行 Kubeless 函数的不同编程语言。单个编程语言将根据版本进一步分为多个运行时。例如，Python 2.7、Python 3.4、Python 3.6 和 Python 3.7 是支持 Python 编程语言的运行时。Kubeless 支持稳定阶段和孵化器阶段的运行时。一旦满足 Kubeless 指定的某些技术要求，运行时将被视为稳定。孵化器运行时被视为处于开发阶段。一旦满足指定的技术要求，运行时维护者可以在 Kubeless GitHub 存储库中创建一个“pull”请求，将运行时从孵化器阶段移至稳定阶段。在撰写本书时，Ballerina、.NET、Golang、Java、Node.js、PHP 和 Python 运行时在稳定阶段可用，JVM 和 Vertx 运行时在孵化器阶段可用。

#### 注意

以下文档定义了稳定运行时的技术要求：[`github.com/kubeless/runtimes/blob/master/DEVELOPER_GUIDE.md#runtime-image-requirements`](https://github.com/kubeless/runtimes/blob/master/DEVELOPER_GUIDE.md#runtime-image-requirements)。

## 创建 Kubernetes 集群

我们需要一个工作的 Kubernetes 集群才能安装 Kubeless 框架。您可以使用 Minikube、Kubeadm 和 Kops 等工具创建自己的 Kubernetes 集群。您还可以使用公共云提供商提供的托管 Kubernetes 集群服务，如 Google Kubernetes Engine（GKE）、Microsoft 的 Azure Kubernetes Service（AKS）和 Amazon Elastic Kubernetes Service（Amazon EKS）来创建 Kubernetes 集群。在接下来的章节中，我们将使用 Minikube 创建自己的 Kubernetes 集群。

### 使用 Minikube 创建 Kubernetes 集群

首先，我们将使用 Minikube 创建我们的 Kubernetes 集群。Minikube 是一个工具，可以在您的个人电脑上安装和运行 Kubernetes。这将在**虚拟机**（**VM**）内创建一个单节点 Kubernetes 集群。Minikube 被软件开发人员用来在本地尝试 Kubernetes，但不建议用于运行生产级别的 Kubernetes 集群。我们将通过以下步骤开始创建我们的 Kubernetes 集群：

1.  安装 VirtualBox。

由于 Minikube 作为虚拟机运行，我们需要安装一个支持虚拟机的 hypervisor。我们将安装由 Oracle Corporation 开发的免费虚拟化软件 Oracle VirtualBox。

#### 注意

可以通过在终端中执行以下命令在 Ubuntu 18.04 上使用 APT 软件包管理器安装 VirtualBox：

`$ sudo apt install virtualbox -y`

1.  执行`virtualbox`命令启动**Oracle VM VirtualBox Manager**，如下截图所示：

```
$ virtualbox
```

![图 7.2：Oracle VM VirtualBox Manager](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_02.jpg)

###### 图 7.2：Oracle VM VirtualBox Manager

1.  安装`minikube`。

现在，我们将安装`Minikube`版本 1.2.0，这是撰写本书时的最新版本。首先，将`minikube`二进制文件下载到本地机器：

```
$ curl -Lo minikube https://storage.googleapis.com/minikube/releases/v1.2.0/minikube-linux-amd64
```

输出如下：

![图 7.3：下载 Minikube 二进制文件](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_03.jpg)

###### 图 7.3：下载 Minikube 二进制文件

1.  然后，为`minikube`二进制文件添加执行权限：

```
$ chmod +x minikube 
```

输出如下：

![图 7.4：为 Minikube 二进制文件添加执行权限](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_04.jpg)

###### 图 7.4：为 Minikube 二进制文件添加执行权限

1.  最后，将 Minikube 二进制文件移动到`/usr/local/bin/`路径位置：

```
$ sudo mv minikube /usr/local/bin/
```

结果如下截图所示：

![图 7.5：将 Minikube 二进制文件移动到路径](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_05.jpg)

###### 图 7.5：将 Minikube 二进制文件移动到路径

1.  验证安装：

```
$ minikube version
```

结果如下截图所示：

![图 7.6：验证 Minikube 版本](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_06.jpg)

###### 图 7.6：验证 Minikube 版本

1.  使用`minikube start`命令启动 Minikube 集群：

```
$ minikube start
```

这将在 VirtualBox 中为 Minikube 创建一个虚拟机，如下所示：

![图 7.7：启动 Minikube](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_07.jpg)

###### 图 7.7：启动 Minikube

现在，在**VirtualBox Manager**窗口中，您可以看到一个名为`minikube`的虚拟机处于运行状态：

![图 7.8：带有 Minikube VM 的 Oracle VirtualBox](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_08.jpg)

###### 图 7.8：带有 Minikube VM 的 Oracle VirtualBox

1.  安装`kubectl`。

现在，我们将安装`kubectl`版本 1.15.0，这是撰写本书时可用的最新版本。首先，将`kubectl`二进制文件下载到您的本地机器：

```
$ curl -LO https://storage.googleapis.com/kubernetes-release/release/v1.15.0/bin/linux/amd64/kubectl
```

这将显示以下输出：

![图 7.9：下载 kubectl 二进制文件](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_09.jpg)

###### 图 7.9：下载 kubectl 二进制文件

1.  然后，为 Minikube 二进制文件添加执行权限：

```
$ chmod +x kubectl
```

以下截图显示了结果：

![图 7.10：为 kubectl 二进制文件添加执行权限](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_10.jpg)

###### 图 7.10：为 kubectl 二进制文件添加执行权限

1.  最后，将 Minikube 二进制文件移动到`/usr/local/bin/`路径位置：

```
$ sudo mv kubectl /usr/local/bin/kubectl
```

输出如下：

![图 7.11：将 kubectl 二进制文件移动到路径](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_11.jpg)

###### 图 7.11：将 kubectl 二进制文件移动到路径

1.  验证安装：

```
$ kubectl version
```

屏幕上将显示以下内容：

![图 7.12：验证 kubectl 版本](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_12.jpg)

###### 图 7.12：验证 kubectl 版本

1.  验证`kubectl` CLI 是否正确指向 Minikube 集群：

```
$ kubectl get pods
```

您应该看到以下输出：

![图 7.13：验证 kubectl 是否指向 Minikube 集群](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_13.jpg)

###### 图 7.13：验证 kubectl 是否指向 Minikube 集群

## 安装 Kubeless

一旦 Minikube Kubernetes 环境准备就绪，我们可以在 Kubernetes 集群之上安装 Kubeless。安装 Kubeless 包括安装三个组件：

+   Kubeless 框架

+   Kubeless CLI

+   Kubeless UI

Kubeless 框架将在 Kubernetes 之上安装所有扩展以支持 Kubeless 功能。这包括 CRD、自定义控制器和部署。Kubeless CLI 用于与 Kubeless 框架交互，执行任务如部署函数、调用函数和创建触发器。Kubeless UI 是 Kubeless 框架的 GUI，可帮助您查看、编辑和运行函数。

### 安装 Kubeless 框架

我们将安装 Kubeless 版本 1.0.3，这是撰写本书时可用的最新版本。

首先，我们需要使用`kubectl create namespace`创建`kubeless`命名空间。这是 Kubeless 使用的默认命名空间，用于存储所有对象：

```
$ kubectl create namespace kubeless
```

结果如下：

![图 7.14：创建 kubeless 命名空间](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_14.jpg)

###### 图 7.14：创建 kubeless 命名空间

在下一步中，我们将安装 Kubeless 框架。我们将使用 Kubeless 提供的 YAML 清单之一来安装框架。Kubeless 提供了多个`yaml`文件，我们必须根据 Kubernetes 环境（例如`rbac`、`non-rbac`或`openshift`）选择正确的`yaml`文件：

```
$ kubectl create -f https://github.com/kubeless/kubeless/releases/download/v1.0.3/kubeless-v1.0.3.yaml 
```

屏幕将显示以下内容：

![图 7.15：安装 Kubeless 框架](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_15.jpg)

###### 图 7.15：安装 Kubeless 框架

上一步将在`kubeless`命名空间中创建多个 Kubernetes 对象。这将创建一个函数对象作为**自定义资源定义**和 Kubeless 控制器作为部署。您可以通过执行以下命令验证这些对象是否正在运行：

```
$ kubectl get pods -n kubeless
$ kubectl get deployment -n kubeless
$ kubectl get customresourcedefinition
```

您将在屏幕上看到以下内容：

![图 7.16：验证 Kubeless 安装](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_16.jpg)

###### 图 7.16：验证 Kubeless 安装

现在，我们已成功完成了 Kubeless 框架的安装。在下一节中，我们将安装 Kubeless CLI。

### 安装 Kubeless CLI

**Kubeless CLI**是针对 Kubeless 框架运行命令的命令行界面。`kubeless function`是最常见的命令，因为它允许您执行诸如部署、调用、更新或删除函数等任务。此外，您还可以通过`kubeless function`命令列出和描述函数。还支持通过`kubeless function`命令检查日志或指标。您还可以通过 Kubeless CLI 管理 Kubeless 触发器、主题和自动缩放。

安装成功 Kubeless 框架后，下一步是安装 Kubeless CLI。我们将使用 Kubeless CLI 版本 1.0.3，这与我们在上一节中安装的 Kubeless 框架版本相同。

首先，我们需要下载 Kubeless CLI zip 文件：

```
$ curl -OL https://github.com/kubeless/kubeless/releases/download/v1.0.3/kubeless_linux-amd64.zip 
```

结果如下：

![图 7.17：下载 Kubeless 二进制文件](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_17.jpg)

###### 图 7.17：下载 Kubeless 二进制文件

接下来，我们将提取 zip 文件：

```
$ unzip kubeless_linux-amd64.zip
```

要更好地理解这一点，请参考以下输出：

![图 7.18：提取 Kubeless 二进制文件](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_18.jpg)

###### 图 7.18：提取 Kubeless 二进制文件

然后，将 Kubeless 可执行文件移动到`/usr/local/bin/`路径位置：

```
$ sudo mv bundles/kubeless_linux-amd64/kubeless /usr/local/bin/
```

以下是您在屏幕上看到的内容：

![图 7.19：将 Kubeless 二进制文件移动到路径](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_19.jpg)

###### 图 7.19：将 Kubeless 二进制文件移动到路径

现在，我们已经成功安装了 Kubeless CLI。您可以通过运行以下命令来验证：

```
$ kubeless version
```

参考以下截图：

![图 7.20：验证 Kubeless 版本](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_20.jpg)

###### 图 7.20：验证 Kubeless 版本

### Kubeless UI

**Kubeless UI** 是 Kubeless 的图形用户界面。它允许您使用易于使用的 UI 创建、编辑、删除和执行 Kubeless 函数。执行以下命令在 Kubernetes 集群中安装 Kubeless UI：

```
$ kubectl create -f https://raw.githubusercontent.com/kubeless/kubeless-ui/master/k8s.yaml
```

这将给你以下输出：

![图 7.21：安装 Kubeless UI](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_21.jpg)

###### 图 7.21：安装 Kubeless UI

安装成功后，执行以下命令在浏览器窗口中打开 Kubeless UI。如果 Kubeless UI 没有显示出来，可以重新加载浏览器窗口，因为创建服务可能需要几分钟时间：

```
$ minikube service ui --namespace kubeless
```

如下所示：

![图 7.22：Kubeless GUI](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_22.jpg)

###### 图 7.22：Kubeless GUI

我们刚刚完成了 Kubeless UI 的安装，它可以用来创建、编辑、删除和执行类似于 Kubeless CLI 的 Kubeless 函数。

## Kubeless 函数

一旦 Kubeless 成功安装，您现在可以忘记底层基础设施，包括虚拟机和容器，只专注于您的函数逻辑。Kubeless 函数是用其中一种支持的语言编写的代码片段。正如我们之前讨论的，Kubeless 支持多种编程语言和版本。您可以执行 `kubeless get-server-config` 命令来获取您的 Kubeless 版本支持的语言运行时列表：

```
$ kubeless get-server-config 
```

结果如下截图所示：

![图 7.23：Kubeless 服务器配置](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_23.jpg)

###### 图 7.23：Kubeless 服务器配置

在接下来的章节中，我们将创建、部署、列出、调用、更新和删除 Kubeless 函数。

### 创建 Kubeless 函数

每个 Kubeless 函数，无论语言运行时如何，都具有相同的格式。它接收两个参数作为输入，并返回一个字符串或对象作为响应。函数的第一个参数是一个事件，其中包括有关事件源的所有信息，例如事件 ID、事件时间和事件类型。`event`对象内的`data`字段包含函数请求的主体。函数的第二个参数命名为`context`，其中包含有关函数的一般信息，例如其名称、超时、运行时和内存限制。

以下是一个返回文本`Welcome to Kubeless World`作为响应的示例 Python 函数：

```
def main(event, context):
    return "Welcome to Kubeless World"  
```

您可以将文件保存为`hello.py`。

### 部署 Kubeless 函数

一旦函数准备就绪，您可以将其部署到 Kubeless 框架中。您可以使用`kubeless function deploy`命令将函数注册到 Kubeless 框架中。为了部署函数，您需要提供一些信息，包括函数名称、函数的运行时、包含函数源代码的文件以及在调用函数时要执行的方法名称：

```
kubeless function deploy hello --runtime python3.7 \
                           --from-file hello.py \
                           --handler hello.main
```

输出如下：

![图 7.24：部署 Kubeless 函数](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_24.jpg)

###### 图 7.24：部署 Kubeless 函数

让我们将这个命令分解成几个部分，以便了解命令的每个部分的作用：

+   `kubeless function deploy hello`：这告诉 Kubeless 注册一个名为`hello`的新函数。我们可以在以后使用这个名称来调用这个函数。

+   `--runtime python3.7`：这告诉 Kubeless 使用 Python 3.7 运行时来运行此函数。

+   `--from-file hello.py`：这告诉 Kubeless 使用`hello.py`文件中可用的代码来创建`hello`函数。如果在执行命令时不在当前文件路径中，需要指定完整的文件路径。

+   `--handler hello.main`：这指定了在调用此函数时要执行的代码文件的名称和方法的名称。这应该是`<file-name>.<function-name>`的格式。在我们的情况下，文件名是`hello`，文件内的函数名是`main`。

您可以通过执行`kubeless function deploy --help`命令找到在部署函数时可用的其他选项。

### 列出 Kubeless 函数

部署函数后，您可以使用`kubeless function list`命令列出函数，以验证函数是否成功部署。您应该看到所有注册函数的详细信息如下：

```
$ kubeless function list
```

以下截图反映了结果：

![图 7.25：使用 Kubeless CLI 列出 Kubeless 函数](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_25.jpg)

###### 图 7.25：使用 Kubeless CLI 列出 Kubeless 函数

#### 注意

同样可以使用`kubeless function ls`命令实现。

如果您希望获取有关特定函数的更详细信息，可以使用`kubeless function describe`命令：

```
$ kubeless function describe hello
```

它产生以下输出：

![图 7.26：描述 Kubeless 函数](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_26.jpg)

###### 图 7.26：描述 Kubeless 函数

由于 Kubeless 函数被创建为 Kubernetes 对象（即自定义资源），您还可以使用 Kubectl CLI 获取有关可用函数的信息。以下是`kubectl get functions`命令的输出：

```
$ kubectl get functions
```

您将得到以下输出：

![图 7.27：使用 kubectl CLI 列出 Kubeless 函数](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_27.jpg)

###### 图 7.27：使用 kubectl CLI 列出 Kubeless 函数

### 调用 Kubeless 函数

现在是时候调用我们的`hello`函数了。您可以使用`kubeless function call`方法来调用 Kubeless 函数。`hello`函数将返回文本`Welcome to Kubeless World`作为响应：

```
$ kubeless function call hello
```

输出如下：

![图 7.28：使用 kubeless CLI 调用 Kubeless 函数](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_28.jpg)

###### 图 7.28：使用 kubeless CLI 调用 Kubeless 函数

恭喜！您已成功执行了您的第一个 Kubeless 函数。

您还可以使用 Kubeless UI 调用 Kubeless 函数。打开 Kubeless UI 后，您可以在左侧看到可用函数的列表。您可以点击`hello`函数以打开它。然后，点击**Run**函数按钮来执行函数。您可以在**Response**部分下看到预期的**Welcome to Kubeless World**响应：

![图 7.29：使用 Kubeless UI 调用 Kubeless 函数](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_29.jpg)

###### 图 7.29：使用 Kubeless UI 调用 Kubeless 函数

#### 注意

Kubeless 函数也可以使用 Kubeless UI 进行更新或删除。

### 更新 Kubeless 函数

成功调用我们的`hello`函数后，现在我们将对其进行更新，以向任何人说*hello*。您可以按照以下方式更新`hello.py`文件：

```
def main(event, context):
   name = event['data']['name']
   return "Hello " +  name
```

然后，您可以执行`kubeless function update`命令来更新我们之前创建的`hello`函数：

```
$ kubeless function update hello --from-file hello.py
```

这将产生以下输出：

![图 7.30：使用 Kubeless CLI 更新 Kubeless 函数](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_30.jpg)

###### 图 7.30：使用 Kubeless CLI 更新 Kubeless 函数

现在在调用`hello`函数时，您必须传递所需的数据：

```
$ kubeless function call hello --data '{"name":"Kubeless World!"}'
```

这是上述代码的输出：

![图 7.31：调用更新后的 Kubeless 函数](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_31.jpg)

###### 图 7.31：调用更新后的 Kubeless 函数

您应该能够在上述命令的输出中看到`Hello Kubeless World!`。

### 删除 Kubeless 函数

如果您想要删除该函数，可以执行`kubeless function delete`命令：

```
$ kubeless function delete hello
```

这将产生以下结果：

![图 7.32：删除 kubeless 函数](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_32.jpg)

###### 图 7.32：删除 kubeless 函数

一旦函数被删除，尝试再次列出函数。它应该会抛出一个错误，如下所示：

```
$ kubeless function list hello
```

我们将看到以下结果：

![图 7.33：验证删除 kubeless 函数](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_33.jpg)

###### 图 7.33：验证删除 kubeless 函数

上述的`kubeless function delete`命令不仅会删除`kubeless`函数，而且在创建 Kubeless 函数时，框架会创建诸如 pod 和 deployment 之类的 Kubernetes 对象。当我们删除 kubeless 函数时，这些对象也将被删除。您可以使用以下命令进行验证：

```
$ kubectl get pods -l function=hello
```

您可以按照以下方式查看结果：

![图 7.34：验证删除](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_34.jpg)

###### 图 7.34：验证删除

现在我们已经学会了如何创建、部署、列出、调用、更新和删除 Kubeless 函数。让我们继续进行一个关于创建您的第一个 Kubeless 函数的练习。

### 练习 21：创建您的第一个 Kubeless 函数

在这个练习中，我们将创建、部署、调用，然后删除一个 Kubeless 函数。执行以下步骤来完成练习：

#### 注意

此练习的代码文件可以在[`github.com/TrainingByPackt/Serverless-Architectures-with-Kubernetes/tree/master/Lesson07/Exercise21`](https://github.com/TrainingByPackt/Serverless-Architectures-with-Kubernetes/tree/master/Lesson07/Exercise21)找到。

1.  创建一个带有示例`hello`函数的文件：

```
$ cat <<EOF >my-function.py
def main(event, context):
    return "Welcome to Serverless Architectures with Kubernetes"
EOF
```

这将呈现以下输出：

![图 7.35：创建 my-function.py 文件](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_35.jpg)

###### 图 7.35：创建 my-function.py 文件

1.  创建`lesson-7`命名空间并部署之前创建的`my-function.py`文件：

```
$ kubectl create namespace lesson-7
$ kubeless function deploy my-function --runtime python3.7 \
                                  --from-file my-function.py \
                                  --handler my-function.main \
                                  --namespace lesson-7
```

输出如下：

![图 7.36：部署 my-function](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_36.jpg)

###### 图 7.36：部署 my-function

1.  验证`my-function`是否已正确部署：

```
$ kubeless function list my-function --namespace lesson-7
```

输出如下：

![图 7.37：验证 my-function 已成功部署](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_37.jpg)

###### 图 7.37：验证 my-function 已成功部署

1.  使用`kubeless` CLI 调用`my-function`：

```
$ kubeless function call my-function --namespace lesson-7
```

它看起来像这样：

![图 7.38：使用 Kubeless CLI 调用 my-function](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_38.jpg)

###### 图 7.38：使用 Kubeless CLI 调用 my-function

1.  删除`my-function`和`lesson-7`命名空间：

```
$ kubeless function delete my-function --namespace lesson-7
$ kubectl delete namespace lesson-7
```

以下是我们得到的：

![图 7.39：使用 Kubeless CLI 删除 my-function](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_39.jpg)

###### 图 7.39：使用 Kubeless CLI 删除 my-function

在这个练习中，首先，我们创建了一个简单的 Python 函数，它返回`Welcome to Serverless Architectures with Kubernetes`字符串作为输出，并将其部署到 Kubeless。然后，我们列出函数以确保它已成功创建。然后，我们调用了`my-function`并成功返回了预期的响应`Welcome to Serverless Architectures with Kubernetes`。最后，我们通过删除函数进行清理。

## Kubeless HTTP 触发器

在前面的部分中，我们讨论了如何使用 Kubeless CLI 调用 Kubeless 函数。在本节中，我们将演示如何通过创建 HTTP 触发器向所有人公开这些函数。

HTTP 触发器用于通过基于 HTTP(S)的调用（如 HTTP `GET`或`POST`请求）执行 Kubeless 函数。当函数部署时，Kubeless 将创建一个与函数关联的 Kubernetes 服务，服务类型为`ClusterIP`；然而，这些服务是不可公开访问的。为了使函数公开可用，我们需要创建一个 Kubeless HTTP 触发器。这将通过使用 Kubernetes 入口规则向所有人公开 Kubeless 函数。

为了运行 HTTP 触发器，您的 Kubernetes 集群必须有一个运行中的入口控制器。一旦入口控制器在 Kubernetes 集群中运行，您可以使用`kubeless trigger http create`命令创建一个 HTTP 触发器：

```
$ kubeless trigger http create <trigger-name> --function-name <function-name>
```

`--function-name`标志用于指定将与 HTTP 触发器关联的函数的名称。

#### 注意

Kubernetes 有许多可用的 ingress 控制器插件，包括 NGINX、Kong、Traefik、F5、Contour 等。您可以在[`kubernetes.io/docs/concepts/services-networking/ingress-controllers/`](https://kubernetes.io/docs/concepts/services-networking/ingress-controllers/)找到它们。

### 练习 22：为 Kubeless 函数创建 HTTP 触发器

在这个练习中，我们将首先为 Minikube 启用 ingress 插件。然后，我们将创建一个要与 HTTP 触发器一起执行的函数。最后，我们将创建一个 HTTP 触发器并使用 HTTP 触发器调用此函数。

#### 注意

此练习的代码文件可以在[`github.com/TrainingByPackt/Serverless-Architectures-with-Kubernetes/tree/master/Lesson07/Exercise22`](https://github.com/TrainingByPackt/Serverless-Architectures-with-Kubernetes/tree/master/Lesson07/Exercise22)找到。

执行以下步骤完成练习：

1.  首先，我们需要在 Minikube 集群中启用`ingress`插件：

```
$ minikube addons enable ingress
```

这显示以下输出：

![图 7.40：启用 Minikube 插件](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_40.jpg)

###### 图 7.40：启用 Minikube 插件

1.  几分钟后，您应该能够看到`kube-system`命名空间中已创建了`nginx-ingress-controller`容器，这是 Kubernetes 系统创建的对象的命名空间：

```
$ kubectl get pod -n kube-system -l app.kubernetes.io/name=nginx-ingress-controller
```

它显示如下：

![图 7.41：列出 nginx-ingress-controller pod](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_41.jpg)

###### 图 7.41：列出 nginx-ingress-controller pod

1.  一旦`nginx-ingress-controller`容器处于运行状态，我们将创建要与 HTTP 触发器一起执行的函数。创建一个名为`greetings.py`的 Python 文件，内容如下：

```
import datetime as dt
def main(event, context):
    currentHour = dt.datetime.now().hour
    greetingMessage = ''
    if currentHour < 12:
        greetingMessage = 'Hello, Good morning!'
    elif currentHour < 18:
        greetingMessage = 'Hello, Good afternoon!'
    else:
        greetingMessage = 'Hello, Good evening!'
    return greetingMessage
```

1.  创建`lesson-7`命名空间并部署之前创建的`greetings.py`：

```
$ kubectl create namespace lesson-7
$ kubeless function deploy greetings --runtime python3.7 \
                                  --from-file greetings.py \
                                  --handler greetings.main \
                                  --namespace lesson-7
```

参考以下输出：

![图 7.42：使用 HTTP 触发器执行函数](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_42.jpg)

###### 图 7.42：使用 HTTP 触发器执行函数

1.  调用函数并验证函数是否提供了预期的输出：

```
$ kubeless function call greetings --namespace lesson-7
```

一旦调用，屏幕将显示以下内容：

![图 7.43：函数输出](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_43.jpg)

###### 图 7.43：函数输出

1.  现在我们可以为`hello`函数创建`http`触发器：

```
$ kubeless trigger http create greetings \
                       --function-name greetings \
                       --namespace lesson-7
```

结果如下：

![图 7.44：创建 HTTP 触发器](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_44.jpg)

###### 图 7.44：创建 HTTP 触发器

1.  列出`http`触发器；您应该能够看到`hello`函数的`http`触发器：

```
$ kubeless trigger http list --namespace lesson-7
```

列表将看起来像这样：

![图 7.45：列出 HTTP 触发器](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_45.jpg)

###### 图 7.45：列出 HTTP 触发器

1.  这将在 Kubernetes 层创建一个`ingress`对象。我们可以使用`kubectl` CLI 列出`ingress`对象：

```
$ kubectl get ingress --namespace lesson-7
```

这将返回以下内容：

![图 7.46：列出入口对象](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_46.jpg)

###### 图 7.46：列出入口对象

1.  您可以看到带有`.nip.io`域名的主机名，我们可以使用它通过 HTTP 访问`greetings`函数。

在这种情况下，主机名是`greetings.192.168.99.100.nip.io`。一旦在 Web 浏览器中打开此主机名，您应该能够在浏览器窗口中看到问候消息（请注意，根据您的本地时间，您的输出可能会有所不同）：

![图 7.47：使用 HTTP GET 请求调用函数](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_47.jpg)

###### 图 7.47：使用 HTTP GET 请求调用函数

## Kubeless PubSub 触发器

Kubeless 函数可以通过向消息系统中的`topics`发送输入消息来调用。这种方法称为 PubSub 机制。目前，Kubeless 支持两种消息系统，即 Kafka 和 NATS。

为了在 Kubeless 中创建 PubSub 触发器，我们需要运行 Kafka 集群或 NATS 集群。一旦 Kafka 或 NATS 集群准备就绪，我们可以使用`kubeless trigger kafka create`来创建 Kafka 触发器，或者使用`kubeless trigger nats create`来创建 NATS 触发器，并将我们的 PubSub 函数与新触发器关联：

```
$ kubeless trigger <trigger-type> create <trigger-name> \
                             --function-selector <label-query> \
                             --trigger-topic <topic-name>
```

让我们讨论命令的每个部分都做了什么：

+   `kubeless trigger <trigger-type> create <trigger-name>`：这告诉 Kubeless 使用提供的名称和触发器类型创建一个 PubSub 触发器。有效的触发器类型是**kafka**和**nats**。

+   `--function-selector <label-query>`：这告诉我们应该将哪个函数与此触发器关联。Kubernetes 标签用于定义这种关系（例如，`--function-selector key1=value1,key2=value2`）。

+   `--trigger-topic <topic-name>`：Kafka 代理将监听此主题，并在向其发布消息时触发函数。

主题是生产者发布消息的地方。Kubeless CLI 允许我们使用`kubeless topic`命令创建主题。这使我们可以轻松地创建、删除、列出主题，并向主题发布消息。

### 练习 23：为 Kubeless 函数创建 PubSub 触发器

在这个练习中，我们将首先在 Minikube 环境中创建一个 Kafka 和 Zookeeper 集群。一旦 Kafka 和 Zookeeper 集群准备就绪，我们将创建一个要执行的函数，并使用 PubSub 触发器。接下来，我们将创建 PubSub 主题。发布消息到创建的主题将执行 Kubeless 函数。执行以下步骤完成练习。

让我们使用 Kafka 的**PubSub**机制调用 Kubeless 函数：

1.  首先，我们将在 Kubernetes 集群中部署**Kafka**和**Zookeeper**：

```
$ kubectl create -f https://github.com/kubeless/kafka-trigger/releases/download/v1.0.2/kafka-zookeeper-v1.0.2.yaml
```

输出将如下所示：

![图 7.48：安装 Kafka 和 Zookeeper](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_48.jpg)

###### 图 7.48：安装 Kafka 和 Zookeeper

1.  验证在`kubeless`命名空间中是否运行了名为`kafka`和`zoo`的两个`statefulset`，用于 Kafka 和 Zookeeper：

```
$ kubectl get statefulset -n kubeless
$ kubectl get services -n kubeless
$ kubectl get deployment -n kubeless
```

将看到以下输出：

![图 7.49：验证 Kafka 和 Zookeeper 安装](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_49.jpg)

###### 图 7.49：验证 Kafka 和 Zookeeper 安装

1.  一旦我们的 Kafka 和 Zookeeper 部署准备就绪，我们可以创建并部署要由`PubSub`触发器触发的函数。创建一个名为`pubsub.py`的文件，并添加以下内容：

```
def main(event, context): 
    return "Invoked with Kubeless PubSub Trigger"  
```

1.  现在让我们部署我们的函数：

```
$ kubeless function deploy pubsub --runtime python3.7 \
                           --from-file pubsub.py \
                           --handler pubsub.main
```

部署将产生以下结果：

![图 7.50：部署 pubsub 函数](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_50.jpg)

###### 图 7.50：部署 pubsub 函数

1.  一旦函数部署完成，我们可以通过列出函数来验证函数是否成功：

```
$ kubeless function list pubsub 
```

列出的函数将如下所示：

![图 7.51：验证 pubsub 函数](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_51.jpg)

###### 图 7.51：验证 pubsub 函数

1.  现在，让我们使用`kubeless trigger kafka create`命令创建`kafka`触发器，并将我们的`pubsub`函数与新触发器关联起来：

```
$ kubeless trigger kafka create my-trigger \
                             --function-selector function=pubsub \
                             --trigger-topic pubsub-topic
```

它将如下所示：

![图 7.52：为 pubsub 函数创建 kafka 触发器](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_52.jpg)

###### 图 7.52：为 pubsub 函数创建 kafka 触发器

1.  现在我们需要一个 Kubeless 主题来发布消息。让我们使用`kubeless topic create`命令创建一个主题。我们需要确保主题名称与我们在上一步中创建`kafka`触发器时提供的`--trigger-topic`相似：

```
$ kubeless topic create pubsub-topic
```

1.  好的。现在是时候测试我们的`pubsub`函数，通过发布事件到`pubsub-topic`来测试：

```
$ kubeless topic publish --topic pubsub-topic --data "My first message"
```

1.  检查`logs`函数以验证`pubsub`函数是否成功调用：

```
$ kubectl logs -l function=pubsub
```

您应该在`output`日志中看到已发布的消息：

```
...
My first message
...
```

要更好地理解这一点，请查看以下输出：

![图 7.53：pubsub 函数的日志](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_53.jpg)

###### 图 7.53：pubsub 函数的日志

## 监视 Kubeless 函数

当我们成功部署了 Kubeless 函数后，我们需要监视我们的函数。可以使用`kubeless function top`命令来实现。此命令将为我们提供以下信息：

+   `NAME`：Kubeless 函数的名称

+   `NAMESPACE`：函数的命名空间

+   `METHOD`：调用函数时的 HTTP 方法类型（例如，GET/POST）

+   `TOTAL_CALLS`：调用次数

+   `TOTAL_FAILURES`：函数失败的次数

+   `TOTAL_DURATION_SECONDS`：此函数执行的总秒数

+   `AVG_DURATION_SECONDS`：此函数执行的平均秒数

+   `MESSAGE`：任何其他消息

以下是`hello`函数的`kubeless function top`输出：

```
$ kubeless function top hello
```

输出将如下所示：

![图 7.54：查看 hello 函数的指标](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_54.jpg)

###### 图 7.54：查看 hello 函数的指标

现在我们已经监视了函数，是时候开始调试了。

## 调试 Kubeless 函数

Kubeless 函数可能在函数生命周期的不同阶段失败（例如，从部署时间到函数执行时间），原因有很多。在本节中，我们将调试一个函数，以确定失败的原因。

为了演示多个错误场景，首先，我们将在`debug.py`文件中创建一个包含以下代码块的示例函数：

```
def main(event, context)
    name = event['data']['name']
    return "Hello " +  name
```

**错误场景 01**

现在，让我们尝试使用`kubeless function deploy`命令部署此函数：

```
$ kubeless function deploy debug --runtime python \
                           --from-file debug.py \
                           --handler debug.main
```

这将导致`Invalid runtime error`，Kubeless 将显示支持的运行时。经过进一步检查，我们可以看到`kubeless function deploy`命令的`--runtime`参数中存在拼写错误。

结果输出将如下所示：

![图 7.55：部署调试函数-错误](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_55.jpg)

###### 图 7.55：部署调试函数-错误

让我们纠正这个拼写错误，并使用`python3.7`运行时重新运行`kubeless function deploy`命令：

```
$ kubeless function deploy debug --runtime python3.7 \
                           --from-file debug.py \
                           --handler debug.main
```

这次，函数将成功部署到 Kubeless 环境中。它应该看起来像下面这样：

![图 7.56：部署调试函数-成功](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_56.jpg)

###### 图 7.56：部署 debug 函数-成功

**错误场景 02**

现在，让我们使用`kubeless function ls`命令来检查函数的状态：

```
$ kubeless function ls debug
```

为了更好地理解这一点，请参考以下输出：

![图 7.57：列出 debug 函数](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_57.jpg)

###### 图 7.57：列出 debug 函数

您可以看到状态为`0/1 NOT READY`。现在，让我们使用`kubectl get pods`命令来检查 debug pod 的状态：

```
$ kubectl get pods -l function=debug
```

现在，参考以下截图输出：

![图 7.58：列出 debug 函数 pods](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_58.jpg)

###### 图 7.58：列出 debug 函数 pods

在这里，debug `pod` 处于`CrashLoopBackOff`状态。这种错误通常是由函数中的语法错误或我们指定的依赖关系引起的。

仔细检查后，我们发现函数头部缺少一个冒号（`:`）来标记函数头部的结束。

让我们纠正这个问题并更新我们的函数。

打开`debug.py`文件，在函数头部添加一个冒号：

```
def main(event, context):
    name = event['data']['name']
    return  "Hello " +  name
```

我们现在将执行`kubeless function update`命令来使用新的代码文件更新函数：

```
$ kubeless function update debug --from-file debug.py
```

输出如下：

![图 7.59：更新 debug 函数](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_59.jpg)

###### 图 7.59：更新 debug 函数

当再次执行`kubeless function ls` debug 时，您应该能够看到函数现在处于`1/1 READY`状态：

![图 7.60：列出 debug 函数](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_60.jpg)

###### 图 7.60：列出 debug 函数

**错误场景 03**

让我们创建一个带有`hello`函数的示例错误场景。为此，您可以通过将`data`部分的键名替换为`username`来调用`hello`函数：

```
$ kubeless function call debug --data '{"username":"Kubeless"}'
```

现在，让我们看看它在屏幕上的样子：

![图 7.61：调用 debug 函数-错误](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_61.jpg)

###### 图 7.61：调用 debug 函数-错误

为了找到此失败的可能原因，我们需要检查函数日志。您可以执行`kubeless function logs`命令来查看`hello`函数的日志：

```
$ kubeless function logs debug 
```

输出如下：

![图 7.62：检查 debug 函数日志](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_62.jpg)

###### 图 7.62：检查 debug 函数日志

输出的前几行显示类似于以下代码块的行，这些是内部健康检查。根据日志，我们可以看到对`/healthz`端点的所有调用都成功返回了`200` HTTP 成功响应代码：

```
10.56.0.1 - - [03/Jul/2019:13:36:17 +0000] "GET /healthz HTTP/1.1" 200 2 "" "kube-probe/1.12+" 0/120
```

接下来，您可以看到错误消息的堆栈跟踪，如下所示，可能的原因是`KeyError: 'name'`错误。函数期望一个`'name'`键，在函数执行期间未找到：

```
Traceback (most recent call last):
  File "/usr/local/lib/python3.7/dist-packages/bottle.py", line 862, in _handle
    return route.call(**args)
  File "/usr/local/lib/python3.7/dist-packages/bottle.py", line 1740, in wrapper
    rv = callback(*a, **ka)
  File "/kubeless.py", line 86, in handler
    raise res
KeyError: 'name'
```

错误消息的最后一行表示函数调用返回了 HTTP 错误`500`：

```
10.56.0.1 - - [03/Jul/2019:13:37:29 +0000] "POST / HTTP/1.1" 500 739 "" "kubeless/v0.0.0 (linux/amd64) kubernetes/$Format" 0/10944
```

#### 注意

`HTTP 500`是 HTTP 协议返回的错误代码，表示**内部服务器错误**。这意味着服务器由于意外情况而无法满足请求。

除了`kubeless function logs`之外，您还可以使用`kubectl logs`命令，它将返回类似的输出。您需要传递`-l`参数，表示标签，以便仅获取特定函数的日志：

```
$ kubectl logs -l function=hello
```

以下将是输出：

![图 7.63：检查调试函数日志](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_63.jpg)

###### 图 7.63：检查调试函数日志

使用`kubectl get functions --show-labels`命令查看与 Kubeless 函数关联的标签。

这将产生以下结果：

![图 7.64：列出函数标签](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_64.jpg)

###### 图 7.64：列出函数标签

让我们纠正错误，并向`debug`函数传递正确的参数：

```
$ kubeless function call debug --data '{"name":"Kubeless"}'
```

现在我们的函数已成功运行，并生成了`Hello Kubeless`作为其输出：

![图 7.65：调用调试函数-成功](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_65.jpg)

###### 图 7.65：调用调试函数-成功

## Kubeless 的 Serverless 插件

Serverless Framework 是一个通用的框架，用于在不同的无服务器提供商上部署无服务器应用程序。Kubeless 的无服务器插件支持部署 Kubeless 函数。除了 Kubeless 的插件之外，Serverless Framework 还支持 AWS Lambda、Azure Functions、Google Cloud Functions、Apache OpenWhisk 和 Kubeless 等无服务器应用程序。

在本节中，我们将安装无服务器框架，并使用无服务器框架提供的 CLI 创建 Kubeless 函数。

在我们开始安装无服务器框架之前，我们需要安装 Node.js 版本 6.5.0 或更高版本作为先决条件。所以，首先让我们安装 Node.js：

```
$ curl -sL https://deb.nodesource.com/setup_12.x | sudo -E bash -
$ sudo apt-get install nodejs -y
```

输出如下：

图 7.66：安装 Node.js 版本 6.5.0

](image/C12607_07_66.jpg)

###### 图 7.66：安装 Node.js 版本 6.5.0

安装后，通过执行以下命令验证 Node.js 版本：

```
$ nodejs -v
```

以下是输出：

![图 7.67：Node.js 版本验证](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_67.jpg)

###### 图 7.67：Node.js 版本验证

一旦 Node.js 安装成功，我们将通过执行以下命令安装 Serverless 框架：

```
$ sudo npm install -g serverless
```

接下来，我们将验证 serverless 版本：

```
$ serverless -v
```

检查输出，如下所示：

![图 7.68：Serverless 版本验证](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_68.jpg)

###### 图 7.68：Serverless 版本验证

我们已经成功完成了 Serverless 框架的安装。现在我们可以开始使用它创建函数。

我们可以使用`serverless create`命令从模板创建一个基本服务。让我们创建一个名为`my-kubeless-project`的项目，如下所示：

```
$ serverless create --template kubeless-python --path my-kubeless-project
```

让我们把命令拆分成几部分以便理解：

+   `--template kubeless-python`：目前，Kubeless 框架有两个模板可用。`kubeless-python`创建一个 Python 函数，`kubeless-nodejs`创建一个 Node.js 函数。

+   `--path my-kubeless-project`：这定义了该函数应该在`my-kubeless-project`目录下创建。查看输出以更好地理解它：

![图 7.69：创建 my-kubeless-project](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_69.jpg)

###### 图 7.69：创建 my-kubeless-project

这个命令将创建一个名为`my-kubeless-project`的目录，并在该目录中创建几个文件。首先，让我们通过执行以下命令进入`my-kubeless-project`目录：

```
$ cd my-kubeless-project
```

以下文件位于`my-kubeless-project`目录中：

+   handler.py

+   serverless.yml

+   package.json

`handler.py`文件包含一个示例 Python 函数，如下所示。这是一个简单的函数，返回一个 JSON 对象和状态码 200：

```
import json
def hello(event, context):
    body = {
        "message": "Go Serverless v1.0! Your function executed successfully!",
        "input": event['data']
    }
    response = {
        "statusCode": 200,
        "body": json.dumps(body)
    }
    return response
```

它还创建了一个`serverless.yml`文件，告诉 serverless 框架在`handler.py`文件中执行`hello`函数。在`provider`部分中，提到这是一个带有`python2.7`运行时的 Kubeless 函数。在`plugins`部分中，它定义了所需的自定义插件，比如`serverless-kubeless`插件：

```
# Welcome to Serverless!
#
# For full config options, check the kubeless plugin docs:
#    https://github.com/serverless/serverless-kubeless
#
# For documentation on kubeless itself:
#    http://kubeless.io
# Update the service name below with your own service name
service: my-kubeless-project
# Please ensure the serverless-kubeless provider plugin is installed globally.
# $ npm install -g serverless-kubeless
#
# ...before installing project dependencies to register this provider.
# $ npm install
provider:
  name: kubeless
  runtime: python2.7
plugins:
  - serverless-kubeless
functions:
  hello:
    handler: handler.hello
```

最后，`package.json`文件包含了`npm`打包信息，比如`dependencies`：

```
{
  "name": "my-kubeless-project",
  "version": "1.0.0",
  "description": "Sample Kubeless Python serverless framework service.",
  "dependencies": {
    "serverless-kubeless": "⁰.4.0"
  },
  "scripts": {
    "test": "echo \"Error: no test specified\" && exit 1"
  },
  "keywords": [
    "serverless",
    "kubeless"
  ],
  "author": "The Kubeless Authors",
  "license": "Apache-2.0"
}
```

您可以根据需要更新这些文件以匹配您的业务需求。在本例中，我们不会更改这些文件。

现在，我们将执行`npm install`命令，安装所有`npm`依赖，比如`kubeless-serverless`插件：

```
$ npm install
```

这个输出如下：

![图 7.70：安装 npm 依赖](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_70.jpg)

###### 图 7.70：安装 npm 依赖项

一旦依赖项准备好，让我们部署服务：

```
$ serverless deploy -v
```

部署服务会为我们提供以下输出：

![图 7.71：部署服务](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_71.jpg)

###### 图 7.71：部署服务

然后，我们可以使用以下命令部署函数：

```
$ serverless deploy function -f hello
```

以下截图显示了输出：

![图 7.72：部署函数](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_72.jpg)

###### 图 7.72：部署函数

当函数成功部署后，我们可以使用`serverless invoke`命令调用函数：

```
$ serverless invoke --function hello -l
```

调用函数会产生以下输出：

![图 7.73：调用函数](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_73.jpg)

###### 图 7.73：调用函数

您还可以使用`kubeless function call`命令来调用此函数：

```
$ kubeless function call hello
```

这样做将提供以下输出：

![图 7.74：使用 kubeless 函数调用来调用函数](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_74.jpg)

###### 图 7.74：使用 kubeless 函数调用来调用函数

完成函数后，使用`serverless remove`来删除函数。

```
$ serverless remove
```

以下是前面代码的输出：

![图 7.75：删除函数](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_75.jpg)

###### 图 7.75：删除函数

#### 注意

如果在调用函数时遇到任何错误，请执行`serverless logs -f hello`命令。

### 活动 7：使用 Kubeless 向 Slack 发布消息

想象一下，您需要一个 Slackbot 来向您的 Slack 频道发布消息。这个 Slackbot 应该能够使用传入的 webhook 集成方法向特定的 Slack 频道发布消息。如果成功向 Slack 发布消息，此机器人将打印成功消息；否则，如果在向 Slack 发送消息时出现任何错误，它将打印错误消息。在这个活动中，我们将创建一个能够向特定 Slack 频道发布消息的 Kubeless 函数。

作为此活动的先决条件，我们需要一个 Slack 工作区，并集成传入的 webhook。执行以下步骤创建一个 Slack 工作区并集成传入的 webhook：

**解决方案-Slack 设置**

1.  创建一个 Slack 工作区。

1.  访问[`slack.com/create`](https://slack.com/create)创建一个工作区。输入您的电子邮件地址，然后单击**创建**。

1.  您应该收到一个六位数的确认码，发送到您在上一页输入的电子邮件中。在工作区中输入收到的代码。

1.  为我们的工作区和 Slack 频道添加合适的名称。

1.  您将被要求填写其他与您合作在同一项目上的人的电子邮件 ID。您可以跳过此部分，或者填写详细信息然后继续。

1.  现在您的 Slack 频道已准备就绪，请点击“在 Slack 中查看您的频道”。

1.  一旦点击，我们应该看到我们的频道。

1.  现在我们将向 Slack 添加`Incoming Webhook`应用程序。从左侧菜单中，在“应用程序”部分下选择“添加应用程序”。

1.  在搜索字段中输入“传入 Webhooks”，然后点击“安装”以安装`Incoming Webhook`应用程序。

1.  点击“添加配置”。

1.  点击“添加传入 WebHooks 集成”。

1.  保存 webhook URL。在编写 Kubeless 函数时，我们会需要它。

#### 注意

有关使用传入 webhook 集成创建 Slack 工作区的详细步骤，以及相应的屏幕截图，请参阅第 422 页。

现在我们准备开始这项活动。执行以下步骤完成此活动：

**活动解决方案**

1.  在任何语言中创建一个函数（由 Kubeless 支持），可以将消息发布到 Slack。在这个活动中，我们将编写一个 Python 函数，执行以下步骤。

1.  使用`requests`库作为依赖项。

1.  向传入的 webhook（在步骤 2 中创建）发送一个`POST`请求，带有输入消息。

1.  打印 post 请求的响应，

1.  将该函数部署到 Kubeless 框架中。

1.  调用该函数。

1.  转到您的 Slack 工作区，验证消息是否成功发布到 Slack 频道。最终输出应如下所示：

![图 7.76：验证消息是否成功发布](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_76.jpg)

###### 图 7.76：验证消息是否成功发布

#### 注意

活动的解决方案可以在第 422 页找到。

## 摘要

在本章中，我们学习了如何使用 Minikube 部署单节点 Kubernetes 集群。然后，我们在 Minikube 集群上安装了 Kubeless 框架、Kubeless CLI 和 Kubeless UI。一旦 Kubernetes 集群和 Kubeless 框架准备就绪，我们就用 Python 创建了我们的第一个 Kubeless 函数，并将其部署到 Kubeless 上。然后，我们讨论了多种调用 Kubeless 函数的方式，包括使用 Kubeless CLI、Kubeless UI、HTTP 触发器、定时触发器和 PubSub 触发器。接下来，我们讨论了在部署 Kubeless 函数时遇到的常见错误场景的调试方法。然后，我们讨论了如何使用无服务器框架部署 Kubeless 函数。最后，在活动中，我们学习了如何使用 Kubeless 函数向 Slack 频道发送消息。

在下一章中，我们将介绍 OpenWhisk，并涵盖 OpenWhisk 动作和触发器。
