# Kubectl：Kubernetes 的命令行手册（一）

> 原文：[`zh.annas-archive.org/md5/86462224726319C40F052928B569BEB0`](https://zh.annas-archive.org/md5/86462224726319C40F052928B569BEB0)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

本书是为那些初次接触通过命令行管理 Kubernetes 的人提供的全面介绍，将帮助您迅速掌握相关知识。

Kubernetes 是一个用于自动化应用部署、扩展和管理的开源容器编排系统，`kubectl`是一个帮助管理它的命令行工具。

# 本书是为谁准备的

本书适用于 DevOps、开发人员、系统管理员以及所有希望使用`kubectl`命令行执行 Kubernetes 功能的人，他们可能了解 Docker，但尚未掌握使用`kubectl`将容器部署到 Kubernetes 的方法。

# 本书涵盖内容

*第一章*，*介绍和安装 kubectl*，提供了对`kubectl`的简要概述以及如何安装和设置它。

*第二章*，*获取有关集群的信息*，教读者如何获取有关集群和可用 API 列表的信息。

*第三章*，*使用节点*，教读者如何获取有关集群节点的信息。

*第四章*，*创建和部署应用程序*，解释了如何创建和安装 Kubernetes 应用程序。

*第五章*，*更新和删除应用程序*，解释了如何更新 Kubernetes 应用程序。

*第六章*，*调试应用程序*，解释了如何查看应用程序日志，`exec`到容器中。

*第七章*，*使用 kubectl 插件*，解释了如何安装`kubectl`插件。

*第八章*，*介绍 Kustomize for kubectl*，讨论了 Kustomize。

*第九章*，*介绍 Helm for Kubernetes*，讨论了 Helm，Kubernetes 包管理器。

*第十章*，*kubectl 最佳实践和 Docker 命令*，涵盖了`kubectl`最佳实践和`kubectl`中的 Docker 等效命令。

# 要充分利用本书

![Table_16411](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/kubectl-cli-k8s-nsh/img/B16411_Preface_Table1.jpg)

**我们建议通过 GitHub 存储库访问代码（链接在** **下一节中可用）。这样做将帮助您避免与复制和粘贴代码相关的任何潜在错误。**

# 下载示例代码文件

您可以从 GitHub 上下载本书的示例代码文件，网址为[`github.com/PacktPublishing/kubectl-Command-Line-Kubernetes-in-a-Nutshell`](https://github.com/PacktPublishing/kubectl-Command-Line-Kubernetes-in-a-Nutshell)。如果代码有更新，将在现有的 GitHub 存储库中进行更新。

我们还有来自我们丰富的书籍和视频目录的其他代码包，可在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)上找到。去看看吧！

# 下载彩色图片

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图片。您可以在这里下载：[`static.packt-cdn.com/downloads/9781800561878_ColorImages.pdf`](https://static.packt-cdn.com/downloads/9781800561878_ColorImages.pdf)。

# 使用的约定

本书中使用了许多文本约定。

`文本中的代码`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。这里有一个例子：“在您的主目录中创建`.kube`目录。”

代码块设置如下：

```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: postgresql
  labels:
    app: postgresql
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```
spec:
  replicas: 1
  selector:
    matchLabels:
      app: postgresql
```

任何命令行输入或输出都是这样写的：

```
$ kubectl version –client --short
Client Version: v1.18.1
```

**粗体**：表示新术语、重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词会在文本中以这种方式出现。这里有一个例子：“我们为节点分配了**标签**和**注释**，并且没有设置**角色**或**污点**。”

提示或重要说明

看起来像这样。


# 第一部分：使用 kubectl 入门

在本节中，您将学习什么是`kubectl`以及如何安装它。

本节包括以下章节：

+   *第一章*，*介绍和安装 kubectl*


# 第一章：介绍和安装 kubectl

Kubernetes 是一个开源的容器编排系统，用于在集群中管理跨多个主机的容器化应用程序。

Kubernetes 提供了应用部署、调度、更新、维护和扩展的机制。Kubernetes 的一个关键特性是，它积极地管理容器，以确保集群的状态始终符合用户的期望。

Kubernetes 使您能够快速响应客户需求，通过扩展或推出新功能。它还允许您充分利用您的硬件。

Kubernetes 包括以下内容：

+   **精简**: 轻量级、简单和易于访问

+   **可移植**: 公共、私有、混合和多云

+   **可扩展**: 模块化、可插拔、可挂钩、可组合和可工具化

+   **自愈**: 自动放置、自动重启和自动复制

Kubernetes 基于 Google 在规模上运行生产工作负载的十五年经验，结合了社区的最佳理念和最佳实践：

![图 1.1 – Kubernetes 架构的一瞥](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/kubectl-cli-k8s-nsh/img/B16411_01_001.jpg)

图 1.1 – Kubernetes 架构的一瞥

管理 Kubernetes 集群的一种方式是`kubectl`—Kubernetes 的命令行工具，它是一个用于访问 Kubernetes 集群的工具，允许您对 Kubernetes 集群运行不同的命令，以部署应用程序、管理节点、排除故障和更多。

在本章中，我们将涵盖以下主要主题：

+   介绍 kubectl

+   安装 kubectl

+   kubectl 命令

# 技术要求

要学习 kubectl，您将需要访问一个 Kubernetes 集群；它可以是这些云集群之一：

+   Google Cloud GKE: [`cloud.google.com/kubernetes-engine`](https://cloud.google.com/kubernetes-engine)

+   Azure AKS EKS: [`azure.microsoft.com/en-us/free/kubernetes-service`](https://azure.microsoft.com/en-us/free/kubernetes-service)

+   AWS EKS: [`aws.amazon.com/eks/`](https://aws.amazon.com/eks/)

+   DigitalOcean DOKS: [`www.digitalocean.com/docs/kubernetes/`](https://www.digitalocean.com/docs/kubernetes/)

或者，它可以是一个本地的：

+   KIND: [`kind.sigs.k8s.io/docs/user/quick-start/`](https://kind.sigs.k8s.io/docs/user/quick-start/)

+   Minikube: [`kubernetes.io/docs/setup/learning-environment/minikube/`](https://kubernetes.io/docs/setup/learning-environment/minikube/)

+   Docker 桌面版：[`www.docker.com/products/docker-desktop`](https://www.docker.com/products/docker-desktop)

在本书中，我们将使用 Google Cloud 的 GKE Kubernetes 集群。

# 介绍 kubectl

您可以使用`kubectl`来部署应用程序，检查和管理它们，检查集群资源，查看日志等。

`kubectl`是一个命令行工具，可以从您的计算机、CI/CD 流水线、操作系统的一部分或作为 Docker 镜像运行。它是一个非常适合自动化的工具。

`kubectl`在`$HOME`文件夹中寻找名为`.kube`的配置文件。在`.kube`文件中，`kubectl`存储访问 Kubernetes 集群所需的集群配置。您还可以设置`KUBECONFIG`环境变量或使用`--kubeconfig`标志指向`kubeconfig`文件。

# 安装 kubectl

让我们看看如何在 macOS、Windows 和 CI/CD 流水线上安装`kubectl`。

## 在 macOS 上安装

在 macOS 上安装`kubectl`的最简单方法是使用 Homebrew 软件包管理器（[`brew.sh/`](https://brew.sh/)）：

1.  要安装，请运行此命令：

```
$ brew install kubectl
```

1.  要查看您安装的版本，请使用此命令：

```
$ kubectl version –client --short
Client Version: v1.18.1
```

## 在 Windows 上安装

要在 Windows 上安装`kubectl`，您可以使用简单的命令行安装程序 Scoop（[`scoop.sh/`](https://scoop.sh/)）：

1.  要安装，请运行此命令：

```
$ scoop install kubectl
```

1.  要查看您安装的版本，请使用此命令：

```
$ kubectl version –client --short
Client Version: v1.18.1
```

1.  在您的主目录中创建`.kube`目录：

```
$ mkdir %USERPROFILE%\.kube
```

1.  导航到`.kube`目录：

```
$ cd %USERPROFILE%\.kube
```

1.  配置`kubectl`以使用远程 Kubernetes 集群：

```
$ New-Item config -type file
```

## 在 Linux 上安装

当您想在 Linux 上使用`kubectl`时，您有两个选项：

+   使用`curl`：

```
$ curl -LO https://storage.googleapis.com/kubernetes-release/release/`curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt`/bin/linux/amd64/kubectl
```

+   如果您的 Linux 系统支持 Docker 镜像，请使用[`hub.docker.com/r/bitnami/kubectl/`](https://hub.docker.com/r/bitnami/kubectl/)。

注意

Linux 是 CI/CD 流水线中非常常见的环境。

# kubectl 命令

要获取支持的`kubectl`命令列表，请运行此命令：

```
$ kubectl --help
```

`kubectl`命令按类别分组。让我们看看每个类别。

## 基本命令

以下是基本的`kubectl`命令：

+   `create`：从文件或`stdin`创建资源；例如，从文件创建 Kubernetes 部署。

+   `expose`：获取服务、部署或 pod 并将其公开为新的 Kubernetes 服务。

+   运行：在集群上运行特定的镜像。

+   `set`：在对象上设置特定功能，例如设置环境变量，在 pod 模板中更新 Docker 镜像等。

+   `explain`：获取资源的文档，例如部署的文档。

+   `get`: 显示一个或多个资源。例如，您可以获取正在运行的 pod 列表或 pod 的 YAML 输出。

+   `edit`: 编辑资源，例如编辑部署。

+   `delete`: 通过文件名、`stdin`、资源和名称或资源和标签选择器删除资源。

## 部署命令

以下是`kubectl`部署命令：

+   `rollout`: 管理资源的部署。

+   `scale`: 为部署、ReplicaSet 或 StatefulSet 设置新的大小。

+   `autoscale`: 自动扩展部署、ReplicaSet 或 StatefulSet。

## 集群管理命令

以下是`kubectl`集群管理命令：

+   `证书`: 修改证书资源。

+   `cluster-info`: 显示集群信息。

+   `top`: 显示资源（CPU/内存/存储）使用情况。

+   `cordon`: 将节点标记为不可调度。

+   `uncordon`: 将节点标记为可调度。

+   `drain`: 准备维护时排空节点。

+   `taint`: 更新一个或多个节点的污点。

## 故障排除和调试命令

以下是`kubectl`故障排除和调试命令：

+   `describe`: 显示特定资源或资源组的详细信息。

+   `logs`: 打印 pod 中容器的日志。

+   `attach`: 连接到正在运行的容器。

+   `exec`: 在容器中执行命令。

+   `port-forward`: 将一个或多个本地端口转发到一个 pod。

+   `proxy`: 运行到 Kubernetes API 服务器的代理。

+   `cp`: 将文件和目录复制到容器中并从容器中复制出来。

+   `auth`: 检查授权。

## 高级命令

以下是`kubectl`高级命令：

+   `diff`: 显示实际版本与将要应用版本的差异。

+   `apply`: 通过文件名或`stdin`将配置应用到资源。

+   `patch`: 使用策略合并补丁更新资源的字段。

+   `replace`: 通过文件名或`stdin`替换资源。

+   `wait`: 等待一个或多个资源的特定条件。

+   `convert`: 在不同的 API 版本之间转换配置文件。

+   `kustomize`: 从目录或远程 URL 构建 kustomization 目标。

## 设置命令

以下是`kubectl`中的设置命令：

+   `label`: 更新资源的标签。

+   `annotate`: 更新资源的注释。

## 其他命令

以下是`kubectl`中使用的其他几个命令：

+   `alpha`: 用于 alpha 功能的命令。

+   `api-resources`: 打印服务器上支持的 API 资源。

+   `api-versions`: 以组/版本的形式打印服务器上支持的 API 版本。

+   `config`: 修改`kube-config`文件。

+   `插件`：提供与插件交互的实用工具。

+   `版本`：打印客户端和服务器版本信息。

从列表中可以看出，命令被分成不同的组。在接下来的章节中，我们将学习大部分但不是所有这些命令。

在撰写本文时，`kubectl`的版本是 1.18；随着更新版本的推出，命令可能会发生变化。

# 总结

在本章中，我们已经学习了`kubectl`是什么，以及如何在 macOS、Windows 和 CI/CD 流水线上安装它。我们还查看了`kubectl`支持的不同命令以及它们的功能。

在下一章中，我们将学习如何使用`kubectl`获取有关 Kubernetes 集群的信息。


# 第二部分：Kubernetes 集群和节点管理

本节解释了如何管理 Kubernetes 集群，如何获取有关集群和节点的信息，以及如何与节点一起工作。

本节包括以下章节：

+   第二章，获取有关集群的信息

+   第三章，与节点一起工作


# 第二章：获取有关集群的信息

当您管理 Kubernetes 集群时，有必要了解它正在运行的 Kubernetes 版本，关于主节点（也称为控制平面）的详细信息，集群上安装的任何插件，以及可用的 API 和资源。由于不同的 Kubernetes 版本支持不同的资源 API 版本，如果未为您的 Ingress 设置正确/不支持的 API 版本，例如，将导致部署失败。

在本章中，我们将涵盖以下主题：

+   集群信息

+   集群 API 版本

+   集群 API 资源

# 集群信息

始终了解安装在 Kubernetes 集群上的 Kubernetes 服务器（API）的版本是一个好习惯，因为您可能希望使用该版本中可用的特定功能。要检查服务器版本，请运行以下命令：

```
$ kubectl version --short
Client Version: v1.18.1
Server Version: v1.17.5-gke.9
```

服务器版本为`v1.17.5`，`kubectl`版本为`v1.18.1`。请注意，服务器版本的`-gke.9`部分是内部 GKE 修订版；正如我们之前提到的，为了本书的目的，使用了 GKE 集群。

重要提示

`kubectl`版本可以是更新的版本；它实际上不必与服务器版本匹配，因为最新版本通常向后兼容。但是，不建议使用较旧的`kubectl`版本与更新的服务器版本。

接下来，让我们通过运行以下命令检查集群服务器信息：

```
$ kubectl cluster-info
Kubernetes master is running at https://35.223.200.75
GLBCDefaultBackend is running at https://35.223.200.75/api/v1/namespaces/kube-system/services/default-http-backend:http/proxy
KubeDNS is running at https://35.223.200.75/api/v1/namespaces/kube-system/services/kube-dns:dns/proxy
Metrics-server is running at https://35.223.200.75/api/v1/namespaces/kube-system/services/https:metrics-server:/proxy
```

在前面的输出日志中，我们看到了以下内容：

+   主端点 IP（`35.223.200.75`），您的`kubectl`连接到 Kubernetes API。

+   已安装插件的列表，在此设置中更多地是针对 GKE 集群的：

a. `GLBDefaultBackend`

b. `KubeDNS`

c. `Metrics-server`

插件列表将在基于云和本地安装之间有所不同。

最后，让我们使用以下命令检查集群节点信息：

```
$ kubectl get nodes
```

上述命令的输出如下截图所示：

![图 2.1 - 显示节点信息的输出](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/kubectl-cli-k8s-nsh/img/B16411_02_001.jpg)

图 2.1 - 显示节点信息的输出

上述命令显示了集群中可用节点的列表，以及它们的状态和 Kubernetes 版本。

# 集群 API 版本

检查可用的集群 API 版本是一个良好的做法，因为每个新的 Kubernetes 版本通常会带来新的 API 版本，并废弃/删除一些旧的版本。

要获取 API 列表，请运行以下命令：

```
$ kubectl api-versions
```

上面命令的输出给出了 API 列表，如下截屏所示：

![图 2.2 - API 列表](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/kubectl-cli-k8s-nsh/img/B16411_02_002.jpg)

图 2.2 - API 列表

您需要知道哪些 API 可以在您的应用程序中使用，否则，如果您使用的 API 版本不再受支持，部署可能会失败。

# 集群资源列表

另一个方便的列表是资源列表，它显示了可用资源、它们的短名称（用于`kubectl`）、资源所属的 API 组、资源是否有命名空间，以及`KIND`类型。

要获取资源列表，请运行以下命令：

```
$ kubectl api-resources
```

上面的命令给出了以下资源列表：

![图 2.3 - 资源列表](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/kubectl-cli-k8s-nsh/img/B16411_02_003.jpg)

图 2.3 - 资源列表

由于列表相当长，我们在上一个截屏中只显示了部分内容。

获取资源列表将帮助您使用短资源名称运行`kubectl`命令，并了解资源属于哪个 API 组。

# 总结

在本章中，我们学会了如何使用`kubectl`获取有关 Kubernetes 集群、可用 API 以及集群中的 API 资源的信息。

在下一章中，我们将看看如何获取 Kubernetes 集群中存在的节点的信息。


# 第三章：使用节点

熟悉 Kubernetes 的人都知道，集群工作负载在节点上运行，所有 Kubernetes pod 都会被调度、部署、重新部署和销毁。

Kubernetes 通过将容器放入 pod 中并将其调度到节点上来运行工作负载。节点可能是虚拟的或物理的机器，这取决于集群的设置。每个节点都有运行 pod 所需的服务，由 Kubernetes 控制平面管理。

节点的主要组件如下：

+   **kubelet**：注册/注销节点到 Kubernetes API 的代理。

+   **容器运行时**：这个运行容器。

+   **kube-proxy**：网络代理。

如果 Kubernetes 集群支持节点自动扩展，那么节点可以按照自动扩展规则的指定而来去：通过设置最小和最大节点数。如果集群中运行的负载不多，不必要的节点将被移除到自动扩展规则设置的最小节点数。当负载增加时，将部署所需数量的节点以容纳新调度的 pod。

有时候您需要排除故障，获取有关集群中节点的信息，找出它们正在运行哪些 pod，查看它们消耗了多少 CPU 和内存等。

总会有一些情况，您需要停止在某些节点上调度 pod，或将 pod 重新调度到不同的节点，或暂时禁用对某些节点的任何 pod 的调度，移除节点，或其他任何原因。

在本章中，我们将涵盖以下主要主题：

+   获取节点列表

+   描述节点

+   显示节点资源使用情况

+   封锁节点

+   排水节点

+   移除节点

+   节点池简介

# 获取节点列表

要开始使用节点，您首先需要获取它们的列表。要获取节点列表，请运行以下命令：

```
$ kubectl get nodes
```

使用上述命令，我们得到以下节点列表：

![图 3.1 – 节点列表](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/kubectl-cli-k8s-nsh/img/B16411_03_001.jpg)

图 3.1 – 节点列表

前面的列表显示我们的 Kubernetes 集群中有三个节点，状态为`Ready`，Kubernetes 版本为`1.17.5-gke.9`。然而，如果您有自动扩展的云支持节点池，您的节点列表可能会有所不同，因为节点将根据集群中运行的应用程序数量而添加/删除。

# 描述节点

`kubectl describe` 命令允许我们获取 Kubernetes 集群中对象的状态、元数据和事件。在本节中，我们将使用它来描述节点。

我们得到了一个节点列表，所以让我们来看看其中的一个：

1.  要描述一个节点，请运行以下命令：

```
$ kubectl describe node gke-kubectl-lab-default-pool-b3c7050d-6s1l
```

由于命令的输出相当庞大，我们将只显示其中的一部分。您可以自行查看完整的输出。

1.  在以下截图中，我们看到了为节点分配的 `标签`（可用于组织和选择对象的子集）和 `注释`（有关节点的额外信息存储在其中），以及 `Unschedulable: false` 表示节点接受将 pod 调度到其上。例如，`标签` 可用于 `节点亲和性`（允许我们根据节点上的标签来限制 pod 可以被调度到哪些节点上）来调度特定节点上的 pod：![图 3.2 – 节点描述 – 检查标签和注释](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/kubectl-cli-k8s-nsh/img/B16411_03_002.jpg)

图 3.2 – 节点描述 – 检查标签和注释

1.  在以下截图中，我们看到了分配的内部和外部 IP、内部 DNS 名称和主机名：![图 3.3 – 节点描述 – 分配的内部和外部 IP](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/kubectl-cli-k8s-nsh/img/B16411_03_003.jpg)

图 3.3 – 节点描述 – 分配的内部和外部 IP

1.  以下截图显示了节点上运行的 pod，以及每个 pod 的 CPU/内存请求和限制：![图 3.4 – 节点描述 – 每个 pod 的 CPU/内存请求和限制](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/kubectl-cli-k8s-nsh/img/B16411_03_004.jpg)

图 3.4 – 节点描述 – 每个 pod 的 CPU/内存请求和限制

1.  以下截图显示了为节点分配的资源：

![图 3.5 – 节点描述 – 为节点分配的资源](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/kubectl-cli-k8s-nsh/img/B16411_03_005.jpg)

图 3.5 – 节点描述 – 为节点分配的资源

正如您所看到的，`$ kubectl describe node` 命令允许您获取有关节点的各种信息。

# 显示节点资源使用情况

了解节点消耗了哪些资源是很方便的。要显示节点使用的资源，请运行以下命令：

```
$ kubectl top nodes
```

我们使用上述命令得到了以下节点列表：

![图 3.6 – 使用的资源最多的节点列表](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/kubectl-cli-k8s-nsh/img/B16411_03_006.jpg)

图 3.6 – 使用的资源最多的节点列表

上一个命令显示节点指标，如 CPU 核心、内存（以字节为单位）以及 CPU 和内存使用百分比。

此外，通过使用`$ watch kubectl top nodes`，您可以在实时监控节点，例如，在对应用进行负载测试或进行其他节点操作时。

注意

`watch`命令可能不在您的计算机上，您可能需要安装它。`watch`命令将运行指定的命令，并每隔几秒刷新屏幕。

# 节点隔离

假设我们要运行一个应用的负载测试，并且希望将一个节点从负载测试中排除。在*获取节点列表*部分看到的节点列表中，我们有三个节点，它们都处于`Ready`状态。让我们选择一个节点，`gke-kubectl-lab-default-pool-b3c7050d-8jhj`，我们不希望在其上调度新的 pod。

`kubectl`有一个名为`cordon`的命令，允许我们使节点不可调度。

```
$ kubectl cordon -h
Mark node as unschedulable.
Examples:
  # Mark node "foo" as unschedulable.
  kubectl cordon foo
Options:
      --dry-run='none': Must be "none", "server", or "client". If client strategy, only print the object that would be
sent, without sending it. If server strategy, submit server-side request without persisting the resource.
  -l, --selector='': Selector (label query) to filter on
Usage:
  kubectl cordon NODE [options]
```

让我们对`gke-kubectl-lab-default-pool-b3c7050d-8jhj`节点进行隔离，然后打印节点列表。要对节点进行隔离，请运行以下命令：

```
$ kubectl cordon gke-kubectl-lab-default-pool-b3c7050d-8jhj
```

在运行上述命令后，我们得到以下输出：

![图 3.8 – 节点隔离](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/kubectl-cli-k8s-nsh/img/B16411_03_007.jpg)

图 3.8 – 节点隔离

我们已经对`gke-kubectl-lab-default-pool-b3c7050d-8jhj`节点进行了隔离，从现在开始，不会再有新的 pod 被调度到该节点，但是已经在该节点上运行的 pod 将继续在该节点上运行。

重要提示

如果被隔离的节点重新启动，那么原先在其上调度的所有 pod 将被重新调度到不同的节点上，因为即使重新启动节点，其就绪状态也不会改变。

如果我们希望再次对节点进行调度，只需使用`uncordon`命令。要对节点进行取消隔离，请运行以下命令：

```
$ kubectl uncordon gke-kubectl-lab-default-pool-b3c7050d-8jhj
```

在运行上述命令后，我们得到以下输出：

![图 3.9 – 取消隔离节点](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/kubectl-cli-k8s-nsh/img/B16411_03_008.jpg)

图 3.9 – 取消隔离节点

从上面的截图中可以看出，`gke-kubectl-lab-default-pool-b3c7050d-8jhj`节点再次处于`Ready`状态，从现在开始新的 pod 将被调度到该节点上。

# 节点排空

您可能希望从将要被删除、升级或重新启动的节点中删除/驱逐所有的 pod。有一个名为`drain`的命令可以做到这一点。它的输出非常长，所以只会显示部分输出：

```
$ kubectl drain –help
```

我们从上述命令中得到以下输出：

![图 3.10 – 部分 kubectl drain – 帮助输出](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/kubectl-cli-k8s-nsh/img/B16411_03_009.jpg)

图 3.10 – 部分 kubectl drain – 帮助输出

从输出中可以看出，您需要传递一些标志才能正确排干节点：`--ignore-daemonsets`和`–force`。

注意

DaemonSet 确保所有指定的 Kubernetes 节点运行与 DaemonSet 中指定的相同的 pod 的副本。无法从 Kubernetes 节点中删除 DaemonSet，因此必须使用`--ignore-daemonsets`标志来强制排干节点。

让我们使用以下命令排干`gke-kubectl-lab-default-pool-b3c7050d-8jhj`节点：

```
$ kubectl drain gke-kubectl-lab-default-pool-b3c7050d-8jhj --ignore-daemonsets –force
```

我们使用上述命令排干节点。此命令的输出如下截图所示：

![图 3.11 - 排水节点](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/kubectl-cli-k8s-nsh/img/B16411_03_010.jpg)

图 3.11 - 排水节点

重要提示

我们传递了`--ignore-daemonsets`标志，以便如果节点上运行有任何 DaemonSets，`drain`命令将不会失败。

所以，我们已经排干了节点。`drain`还做了什么？它还会封锁节点，因此不会再有 pod 被调度到该节点上。

现在我们准备删除节点。

# 删除节点

`gke-kubectl-lab-default-pool-b3c7050d-8jhj`节点已经被排干，不再运行任何部署、pod 或 StatefulSets，因此现在可以轻松删除。

我们使用`delete node`命令来执行：

```
$ kubectl delete node gke-kubectl-lab-default-pool-b3c7050d-8jhj
```

我们使用上述命令删除节点。此命令的输出如下截图所示：

![图 3.12 - 删除节点](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/kubectl-cli-k8s-nsh/img/B16411_03_011.jpg)

图 3.12 - 删除节点

从`kubectl get nodes`的输出中可以看出，该节点已从 Kubernetes API 中注销并被删除。

重要提示

实际节点删除取决于您的 Kubernetes 设置。在云托管的集群中，节点将被注销和删除，但如果您运行的是自托管的本地 Kubernetes 集群，则实际节点将不会被删除，而只会从 Kubernetes API 中注销。

此外，当您在云设置中指定集群大小时，新节点将在一段时间后替换已删除的节点。

让我们运行`kubectl get nodes`来检查节点：

![图 3.13 - 节点列表](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/kubectl-cli-k8s-nsh/img/B16411_03_012.jpg)

图 3.13 - 节点列表

几分钟后，我们看到第三个节点又回来了，甚至名称都一样。

# 节点池简介

将 Kubernetes 作为托管服务的云提供商支持节点池。让我们学习一下它们是什么。

节点池只是具有相同计算规格和相同 Kubernetes 节点标签的一组 Kubernetes 节点，没有其他太花哨的东西。

例如，我们有两个节点池：

+   带有 `node-pool: default-pool` 节点标签的默认池

+   带有 `node-pool: web-app` 节点标签的 web 应用程序池

Kubernetes 节点标签可以用于节点选择器和 Node Affinity，以控制工作负载如何调度到您的节点。

我们将在*第五章*中学习如何使用 Node Affinity 来使用 Kubernetes 节点池，*更新和删除应用程序*。

# 摘要

在本章中，我们学习了如何使用 `kubectl` 列出集群中运行的节点，获取有关节点及其资源使用情况的信息；我们看到了如何对节点进行 cordon、drain 和删除操作；并且我们对节点池进行了介绍。

我们学到了可以应用于实际场景中的新技能，用于对 Kubernetes 节点进行维护。

在下一章中，我们将学习如何使用 `kubectl` 在 Kubernetes 集群中创建和部署应用程序。


# 第三部分：应用程序管理

本节介绍如何管理 Kubernetes 应用程序，包括创建、更新、删除、查看和调试应用程序。

本节包括以下章节：

+   第四章，创建和部署应用程序

+   第五章，更新和删除应用程序

+   第六章，调试应用程序


# 第四章：创建和部署应用程序

在前几章中，我们已经了解了 Kubernetes 节点。让我们最终使用 Kubernetes 部署一个应用程序，扩展该应用程序，并为其创建一个服务。

Kubernetes 部署是从 Docker 镜像部署应用程序的一种方式，我们将在示例应用程序中使用它。

Kubernetes 支持几种容器运行时，所有这些容器运行时都可以运行 Docker 镜像：

+   Docker

+   CRI-O

+   Containerd

在本章中，我们将涵盖以下主题：

+   Pod 的介绍

+   创建部署

+   创建服务

+   扩展应用程序

# Pod 的介绍

Pod 是一组共享卷的应用程序容器的共同组。

一个 Pod 中的应用程序都使用相同的网络命名空间、IP 地址和端口空间。它们可以使用 localhost 找到彼此并进行通信。每个 Pod 在一个扁平的共享网络命名空间中都有一个 IP 地址，可以与网络中的其他物理计算机和容器进行完全通信。

Pod 是可以使用 Kubernetes 创建、调度和管理的最小部署单元。Pod 也可以单独创建。由于 Pod 没有受管生命周期，如果它们死亡，它们将不会被重新创建。因此，建议即使创建单个 Pod，也使用部署。

Pod 也用于 DaemonSets、StatefulSets、Jobs 和 CronJobs：

![图 4.1 - 具有两个容器的 Pod](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/kubectl-cli-k8s-nsh/img/B16411_04_001.jpg)

图 4.1 - 具有两个容器的 Pod

上图显示了一个具有两个容器的 Pod。Pod 中的容器共享相同的 Linux 网络命名空间以及以下内容：

+   IP 地址

+   本地主机

+   **IPC**（**进程间通信**）

让我们继续进行部署，这更适合于真实世界的应用程序部署。

# 创建部署

Kubernetes 部署提供了 ReplicaSets 的更新，确保指定数量的 Pod（副本）始终运行：

![图 4.2 - 具有三个 Pod 的部署](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/kubectl-cli-k8s-nsh/img/B16411_04_002.jpg)

图 4.2 - 三个 Pod 的部署

上图显示了一个具有三个 Pod 的部署；ReplicaSet 将尝试始终保持三个 Pod 运行。当然，如果 Kubernetes 集群中没有空闲资源，运行的 Pod 副本可能无法匹配所需的副本计数。

有几种方法可以创建 Kubernetes 部署 - 让我们来探索一下。最简单的方法是使用`$ kubectl create deployment`。

让我们创建一个`nginx`部署：

```
$ kubectl create deployment
deployment.apps/nginx created
```

让我们检查创建的`nginx`部署：

```
$ kubectl get deployment
NAME    READY   UP-TO-DATE   AVAILABLE   AGE
nginx   1/1     1            1           19d
```

让我们检查创建的`nginx` pod：

```
$ kubectl get pods
NAME                    READY   STATUS    RESTARTS   AGE
nginx-86c57db685-c9s49  1/1     Running   0          10d
```

上述命令创建了一个带有一个`nginx-86c57db685-c9s49` pod 的`nginx`部署。

看起来几乎太容易了，对吧？一个命令，嘭：你的部署正在运行。

重要提示

`kubectl create deployment`命令仅建议用于测试图像，因为在那里您不指定部署模板，并且对于您可能想要设置的任何其他设置，您没有太多控制。

让我们使用`$ kubectl apply`命令从文件部署：

1.  我们有一个名为`deployment.yaml`的文件，内容如下：

```
$ cat deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx
  labels:
    app: nginx
spec:
  replicas: 1
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
      - image: nginx:1.18.0
        imagePullPolicy: IfNotPresent
        name: nginx
```

当使用前面的文件与`kubectl`时，它将部署与我们使用`$ kubectl create deployment`命令相同的`nginx`部署，但在这种情况下，稍后我们可以根据需要更新文件并升级部署。

1.  让我们删除之前安装的部署：

```
$ kubectl delete deployment nginx
deployment.apps "nginx" deleted
```

1.  这次让我们使用`deployment.yaml`文件重新部署：

```
$ kubectl apply –f deployment.yaml
deployment.apps/nginx created
$ kubectl get deployment
NAME    READY   UP-TO-DATE   AVAILABLE   AGE
nginx   1/1     1            1           17s
$ kubectl get pods
NAME                    READY   STATUS    RESTARTS   AGE
nginx-7df9c6ff5-pnnr6   1/1     Running   0          25s
```

从上述命令中可以看出，我们部署了一个安装了一个 pod（副本），但这次我们使用了文件中的模板。

下图显示了一个带有三个 pod 的部署；ReplicaSet 将尝试始终保持三个 pod 运行。同样，如果 Kubernetes 集群中没有空闲资源，运行的 pod 副本可能不会与所需的副本计数匹配：

![图 4.3 – Kubernetes 节点](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/kubectl-cli-k8s-nsh/img/B16411_04_003.jpg)

图 4.3 – Kubernetes 节点

让我们看看如何创建一个服务。

# 创建一个服务

Kubernetes 服务为一组 pod 提供单一稳定的名称和地址。它们充当基本的集群内负载均衡器。

大多数 pod 都设计为长时间运行，但当一个单独的进程死掉时，pod 也会死掉。如果它死掉，部署会用一个新的 pod 来替换它。每个 pod 都有自己专用的 IP 地址，这允许容器使用相同的端口（例外情况是使用 NodePort），即使它们共享同一个主机。但当部署启动一个 pod 时，该 pod 会获得一个新的 IP 地址。

这就是服务真正有用的地方。服务附加到部署上。每个服务都被分配一个虚拟 IP 地址，直到服务死掉都保持不变。只要我们知道服务的 IP 地址，服务本身将跟踪部署创建的 pod，并将请求分发给部署的 pod。

通过设置服务，我们可以获得一个内部的 Kubernetes DNS 名称。此外，当有多个 ReplicaSet 时，服务还可以充当集群内的负载均衡器。有了服务，您还可以将应用程序暴露到互联网，当服务类型设置为 LoadBalancer 时：

![图 4.4 - Kubernetes 节点](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/kubectl-cli-k8s-nsh/img/B16411_04_004.jpg)

图 4.4 - Kubernetes 节点

上述图解释了服务的工作原理。

由于我们的应用程序已经运行起来了，让我们为其创建一个 Kubernetes 服务：

1.  让我们从运行以下命令开始：

```
$ kubectl expose deployment nginx --port=80 --target-port=80
service/nginx exposed
```

我们使用了端口`80`，并且在该端口上，`nginx`服务被暴露给其他 Kubernetes 应用程序；`target-port=80`是我们的`nginx`容器端口。我们使用端口为`80`的容器，因为我们在*第三章*中部署的官方`nginx`Docker 镜像（[`hub.docker.com/_/nginx`](https://hub.docker.com/_/nginx)）使用端口`80`。

1.  让我们检查创建的`nginx`服务：

```
$ kubectl get service
NAME         TYPE        CLUSTER-IP    EXTERNAL-IP   PORT(S)
kubernetes   ClusterIP   10.16.0.1     <none>        443/TCP
nginx        ClusterIP   10.16.12.233  <none>        80/TCP
$ kubectl describe service nginx
Name:              nginx
Namespace:         default
Labels:            app=nginx
Annotations:       cloud.google.com/neg: {"ingress":true}
Selector:          app=nginx
Type:              ClusterIP
IP:                10.16.12.233
Port:              <unset>  80/TCP
TargetPort:        80/TCP
Endpoints:         10.8.0.133:80
Session Affinity:  None
Events:            <none>
```

上述`kubectl get service`命令显示了服务列表，`kubectl describe service nginx`描述了服务。

我们可以看到一些东西：

+   服务的名称与我们暴露的部署相同，都是`nginx`。

+   `Selector: app=nginx`与`nginx`部署中的`matchLabels`是相同的；这就是服务如何知道如何连接到正确的部署。

+   当没有提供“-type”标志时，`Type: ClusterIP`是默认的服务类型。

重要提示

使用`kubectl expose`命令看起来是为应用程序设置服务的一种简单方法。但是，我们无法将该命令纳入 Git 控制，也无法更改服务设置。对于测试目的，这是可以的，但对于运行真实应用程序来说就不行了。

让我们使用`$ kubectl apply`命令从文件部署。

我们有一个名为`service.yaml`的文件，我们将使用它来更新服务：

```
$ cat service.yaml
apiVersion: v1
kind: Service
metadata:
  name: nginx
  labels:
    app: nginx
spec:
  type: ClusterIP
  ports:
  - port: 80
    protocol: TCP
    targetPort: 80
  selector:
    app: nginx
```

这次，让我们保留使用`kubectl expose`创建的服务，并看看我们是否可以将`service.yaml`文件中的更改应用到我们创建的服务上。

要部署服务，我们运行以下命令：

```
$ kubectl apply –f service.yaml
Warning: kubectl apply should be used on resource created by ether kubectl create –save-config or kubetl apply
service/nginx configured
```

我们收到了一个警告（首先我们使用了`kubectl expose`命令，然后我们尝试从文件更新服务），但我们的更改成功应用到了服务上，从现在开始我们可以使用`service.yaml`来对`nginx`服务进行更改。

提示

当您使用`kubectl expose`创建服务时，可以使用`kubectl get service nginx -o yaml > service.yaml`命令将其模板导出到 YAML 文件，并将该文件用于可能需要进行的将来更改。

要导出`nginx`服务，请运行以下命令：

```
$ kubectl get service nginx -o yaml
```

前述命令的输出如下所示：

![图 4.5 - 导出 nginx 服务](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/kubectl-cli-k8s-nsh/img/B16411_04_005.jpg)

图 4.5 - 导出 nginx 服务

将其内容复制到一个文件中，然后您应该删除以下部分，这些部分是由`kubectl`生成的，不需要在那里：

+   `annotations`

+   `creationTimestamp`

+   `resourceVersion:`

+   `selfLink`

+   `uid`

+   `状态`

重要提示

您还可以使用`kubectl get deployment nginx -o yaml > deployment.yaml`命令将部署的模板导出到 YAML 文件。

# 扩展应用程序

在上一节中，我们部署了一个副本的应用程序；让我们将其部署扩展到两个副本。

运行以下命令来扩展我们的部署：

```
$ kubectl scale deployment nginx –replicas=2
deployment.apps/nginx scaled
$ kubectl get deployment nginx
NAME    READY   UP-TO-DATE   AVAILABLE   AGE
nginx   2/2     2            2           5d17h
$ kubectl get pods
NAME                    READY   STATUS    RESTARTS   AGE
nginx-7df9c6ff5-chnrk   1/1     Running   0          29s
nginx-7df9c6ff5-s65dq   1/1     Running   0          5d17h
```

从前述输出中，我们可以看到`$ kubectl get deployment nginx`命令显示`nginx`部署有两个副本。通过`$ kubectl get pods`，我们看到两个 pod；其中一个刚刚不到一分钟。

这是一个很好的命令来扩展部署，对于测试目的很方便。让我们尝试使用`deployment.yaml`文件来扩展部署。

这次，让我们使用`deployment.yaml`文件来扩展到三个副本：

1.  使用三个副本更新`deployment.yaml`：

```
...
spec:
  replicas: 3
...
```

1.  运行与之前相同的命令：

```
$ kubectl apply –f deployment.yaml
deployment.apps/nginx configured
$ kubectl get deployment nginx
NAME    READY   UP-TO-DATE   AVAILABLE   AGE
nginx   3/3     3            3           5d17h
$ kubectl get pods
NAME                    READY   STATUS    RESTARTS   AGE
nginx-7df9c6ff5-chnrk   1/1     Running   0          21m
nginx-7df9c6ff5-s65dq   1/1     Running   0          5d17h
nginx-7df9c6ff5-tk7g4   1/1     Running   0          22s
```

很好：我们已经从`deployment.yaml`文件中将`nginx`部署更新为三个副本。

该服务将以循环方式在三个 pod 之间分发所有传入的请求。

# 总结

在本章中，我们已经学会了如何使用`kubectl`创建、部署和扩展应用程序。本章中学到的新技能现在可以用于部署真实世界的应用程序。

在下一章中，我们将学习如何对部署的应用程序进行更高级的更新。


# 第五章：更新和删除应用程序

在上一章中，我们学习了如何部署应用程序及其服务，以及如何扩展部署副本。现在让我们学习一些更高级的方法来更新您的应用程序。

在本章中，我们将学习如何将应用程序更新到新版本，以及如果发布是错误的，如何回滚。我们将看到如何将应用程序分配给特定节点，以高可用模式运行应用程序，如何使应用程序在互联网上可用，以及在需要的情况下如何删除应用程序。

在本章中，我们将涵盖以下主要主题：

+   发布新的应用程序版本

+   回滚应用程序发布

+   将应用分配给特定节点（节点亲和性）

+   将应用程序副本调度到不同的节点（Pod 亲和性）

+   将应用程序暴露给互联网

+   删除一个应用程序

# 部署新的应用程序版本

在上一章中，我们使用了`nginx v1.18.0` Docker 镜像部署了一个应用程序。在本节中，让我们将其更新为`nginx v1.19.0`：

要更新`nginx` Docker 镜像标签，请运行以下命令：

```
$ kubectl set image deployment nginx nginx=nginx:1.19.0 \
 --record
deployment.apps/nginx image updated
$ kubectl rollout status deployment nginx
deployment "nginx" successfully rolled out
$ kubectl get deployment nginx
NAME    READY   UP-TO-DATE   AVAILABLE   AGE
nginx   3/3     3            3           5d19h
$ kubectl get pods
NAME                    READY   STATUS    RESTARTS   AGE
nginx-6fd8f555b-2mktp   1/1     Running   0          60s
nginx-6fd8f555b-458cl   1/1     Running   0          62s
nginx-6fd8f555b-g728z   1/1     Running   0          66s
```

`$ kubectl rollout status deployment nginx`命令将显示滚动状态为成功、失败或等待：

```
deployment "nginx" successfully rolled out
```

这是检查部署的滚动状态的一种方便方式。

通过运行以下命令来确保部署已更新为`nginx` v1.19.0：

```
$ kubectl describe deployment nginx
```

上述命令的输出可以在以下截图中看到：

![图 5.1 - 描述部署的输出](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/kubectl-cli-k8s-nsh/img/B16411_05_001.jpg)

图 5.1 - 描述部署的输出

是的，它已更新为 v1.19.0，正如我们在`Pod Template`部分中所看到的。现在，让我们使用`deployment.yaml`文件更新 Docker 镜像。

使用新的 Docker `image`标签更新`deployment.yaml`文件：

```
...
spec:
  containers:
  -image: nginx:1.19.0
...
```

运行`$ kubectl apply -f deployment.yaml`命令：

```
$ kubectl apply -f deployment.yaml
deployment.apps/nginx configured
$ kubectl rollout status deployment nginx
deployment "nginx" successfully rolled out
$ kubectl get deployment nginx
NAME    READY   UP-TO-DATE   AVAILABLE   AGE
nginx   3/3     3            3           5d19h
$ kubectl get pods
NAME                    READY   STATUS    RESTARTS   AGE
nginx-6fd8f555b-2mktp   1/1     Running   0          12m
nginx-6fd8f555b-458cl   1/1     Running   0          12m
nginx-6fd8f555b-g728z   1/1     Running   0          12m
```

运行`$ kubectl get pods`命令显示，由于我们应用了与之前相同的 Docker 镜像标签，因此 Pods 没有发生变化，因此 Kubernetes 足够聪明，不会对`nginx`部署进行任何不必要的更改。

# 回滚应用程序发布

总会有一些情况（例如代码中的错误、为最新发布提供了错误的 Docker 标签等），当您需要将应用程序发布回滚到先前的版本。

这可以通过`$ kubectl rollout undo deployment nginx`命令，然后跟随`get`和`describe`命令来完成：

![图 5.2 - 部署发布回滚](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/kubectl-cli-k8s-nsh/img/B16411_05_002.jpg)

图 5.2 - 部署发布回滚

上述输出显示版本为`Image: nginx:1.18.0`，因此回滚成功了。

我们还可以检查部署的回滚历史：

```
$ kubectl rollout history deployment nginx
deployment.apps/nginx
REVISION  CHANGE-CAUSE
1         <none>
2         <none>
```

我们还可以回滚到特定的修订版本：

```
$ kubectl rollout undo deployment nginx –to-revision=1
deployment.apps/nginx rolled back
```

很好，我们已经学会了如何回滚部署的发布。

# 将应用程序分配给特定节点（节点亲和性）

有些情况下，Kubernetes 集群具有不同规格的不同节点池，例如以下情况：

+   有状态的应用程序

+   后端应用程序

+   前端应用程序

让我们将`nginx`部署重新调度到专用节点池：

1.  要获取节点列表，请运行以下命令：

```
$ kubectl get nodes
```

上述命令给出了以下输出：

![图 5.3 - 节点池列表](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/kubectl-cli-k8s-nsh/img/B16411_05_003.jpg)

图 5.3 - 节点池列表

1.  接下来，让我们检查一个名为`gke-kubectl-lab-we-app-pool`的节点。运行以下命令：

```
$ kubectl describe node gke-kubectl-lab-we-app-pool-1302ab74-pg34
```

上述命令的输出如下截图所示：

![图 5.4 - 节点标签](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/kubectl-cli-k8s-nsh/img/B16411_05_004.jpg)

图 5.4 - 节点标签

1.  在这里，我们有一个`node-pool=web-app`标签，它对于`gke-kubectl-lab-we-app-pool`池的所有节点都是相同的。

1.  让我们使用`nodeAffinity`规则更新`deployment.yaml`文件，这样`nginx`应用程序只会被调度到`gke-kubectl-lab-we-app-pool`：

```
...
spec:
  affinity:
    nodeAffinity:
      requiredDuringSchedulingIgnoredDuringExecution:
        nodeSelectorTerms:
        - matchExpressions:
          - key: node-pool
            operator: In
            values:
            - "web-app"
containers:
...
```

1.  要部署更改，请运行`$ kubectl apply -f deployment.yaml`命令，然后按照以下截图中显示的`get`命令：![图 5.5 - 节点亲和性](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/kubectl-cli-k8s-nsh/img/B16411_05_005.jpg)

图 5.5 - 节点亲和性

很好，Pod 被调度到了`gke-kubectl-lab-we-app-pool`。

提示

我们使用了`-o wide`标志，它允许我们显示有关 Pod 的更多信息，例如其 IP 和所在的节点。

1.  让我们删除一个 Pod 来验证它是否被调度到`gke-kubectl-lab-we-app-pool`：

```
$ kubectl delete pod nginx-55b7cd4f4b-tnmpx
```

让我们再次获取 Pod 列表：

![图 5.6 - 带节点的 Pod 列表](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/kubectl-cli-k8s-nsh/img/B16411_05_006.jpg)

图 5.6 - 带节点的 Pod 列表

上述截图显示了 Pod 列表，以及 Pod 所在的节点。很好，新的 Pod 被调度到了正确的节点池。

# 将应用程序副本调度到不同的节点（Pod 亲和性）

使用`nodeAffinity`不能确保下次 pod 被调度到不同的节点上，对于真正的应用程序高可用性，最佳实践是确保应用程序 pod 被调度到不同的节点上。如果其中一个节点宕机/重启/替换，所有的 pod 都运行在该节点上将导致应用程序崩溃，其服务不可用。

让我们使用`podAntiAffinity`规则更新`deployment.yaml`文件，以便`nginx`应用程序只被调度到`gke-kubectl-lab-we-app-pool`上，并且被调度到不同的节点上：

```
...
spec:
  affinity:
    nodeAffinity:
      requiredDuringSchedulingIgnoredDuringExecution:
        nodeSelectorTerms:
        - matchExpressions:
          - key: node-pool
            operator: In
            values:
            - "web-app"
    podAntiAffinity:
      requiredDuringSchedulingIgnoredDuringExecution:
      - labelSelector:
          matchExpressions:
          - key: app
            operator: In
            values:
            - nginx
          topologyKey: "kubernetes.io/hostname"
containers:
...
```

要部署新更改，运行`$ kubectl apply -f deployment.yaml`命令，然后运行`get`命令，如下截图所示：

![图 5.7 - 节点亲和力](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/kubectl-cli-k8s-nsh/img/B16411_05_007.jpg)

图 5.7 - 节点亲和力

如你所见，pod 再次被重新调度，因为我们添加了`podAntiAffinity`规则：

![图 5.8 - 节点亲和力 pod 被重新调度](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/kubectl-cli-k8s-nsh/img/B16411_05_008.jpg)

图 5.8 - 节点亲和力 pod 被重新调度

如你所见，pod 正在运行在不同的节点上，并且`podAntiAffinity`规则将确保 pod 不会被调度到同一个节点上。

# 将应用程序暴露给互联网

到目前为止，工作得很好，为了完成本章，让我们使我们的应用程序可以通过互联网访问。

我们需要使用`type: LoadBalancer`更新`service.yaml`，这将创建一个带有外部 IP 的 LoadBalancer。

注意

LoadBalancer 功能取决于供应商集成，因为外部 LoadBalancer 是由供应商创建的。因此，如果在 Minikube 或 Kind 上本地运行，你永远不会真正获得外部 IP。

使用以下内容更新`service.yaml`文件：

```
...
spec:
  type: LoadBalancer
...
```

要部署新更改，运行`$ kubectl apply -f service.yaml`命令，然后运行`get`命令，如下截图所示：

![图 5.9 - 带有待处理 LoadBalancer 的服务](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/kubectl-cli-k8s-nsh/img/B16411_05_009.jpg)

图 5.9 - 带有待处理 LoadBalancer 的服务

我们看到`pending`作为状态取决于云提供商，LoadBalancer 的配置可能需要最多 5 分钟。一段时间后再次运行`get`命令，你会看到 IP 已经分配，如下截图所示：

![图 5.10 - 带有 LoadBalancer 的服务](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/kubectl-cli-k8s-nsh/img/B16411_05_010.jpg)

图 5.10 - 带有 LoadBalancer 的服务

为了确保应用程序正常工作，让我们在浏览器中打开 IP `104.197.177.53`：

![图 5.11 - 浏览器中的应用程序](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/kubectl-cli-k8s-nsh/img/B16411_05_011.jpg)

图 5.11 - 浏览器中的应用程序

哇！我们的应用程序可以从互联网访问。

重要提示

上面的示例显示了如何将应用程序暴露在互联网上，这并不安全，因为它使用的是 HTTP。为了保持示例简单，我们使用了 HTTP，但现实世界的应用程序应该只使用 HTTPS。

# 删除应用程序

有时，您需要删除一个应用程序，让我们看一下如何做到这一点的几种选项。

在前面的部分中，我们部署了部署和服务。让我们回顾一下我们部署了什么。

要检查部署，请运行以下命令：

```
$ kubectl get deployment
NAME    READY   UP-TO-DATE   AVAILABLE   AGE
nginx   3/3     3            3           6d17h
```

要检查活动服务，请运行以下命令：

```
$ kubectl get service
NAME         TYPE         CLUSTER-IP    EXTERNAL-IP     PORT(S)
kubernetes   ClusterIP    10.16.0.1     <none>          443/TCP
nginx        LoadBalancer 10.16.12.134  104.197.177.53  80:30295/TCP
```

我们有一个名为`nginx`的部署和一个名为`nginx`的服务。

首先，让我们使用以下命令删除`nginx`服务：

```
$ kubectl delete service nginx
service "nginx" deleted
$ kubectl get service
NAME         TYPE         CLUSTER-IP    EXTERNAL-IP     PORT(S)
kubernetes   ClusterIP    10.16.0.1     <none>          443/TCP
```

正如您在上面的截图中所看到的，`nginx`服务已被删除，该应用程序不再暴露在互联网上，也可以安全地被删除。要删除`nginx`部署，请运行以下命令：

```
$ kubectl delete deployment nginx
deployment.apps "nginx" deleted
$ kubectl get deployment
No resources found in default namespace.
```

使用几个命令轻松删除应用程序的部署资源。

但是，如果您有一个图像，其中安装了不止两个资源，您会为每个资源运行删除命令吗？当然不会，有一种更简单的方法可以做到这一点。

由于我们已经删除了部署和服务，让我们再次部署它们，这样我们就有东西可以再次删除。您需要将`deployment.yaml`和`service.yaml`放入某个文件夹中，例如`code`。

这将允许您一起管理多个资源，就像在一个目录中有多个文件一样。

注意

您还可以在单个 YAML 文件中拥有多个 YAML 条目（使用`---`分隔符）。

要使用相同的命令安装部署和服务，请运行以下命令：

```
$ kubectl apply –f code/
deployment.apps/nginx created
service/nginx created
```

要检查部署和服务，请运行以下命令：

```
$ kubectl get deployment
NAME    READY   UP-TO-DATE   AVAILABLE   AGE
nginx   3/3     3            3           13s
$ kubectl get service
NAME         TYPE         CLUSTER-IP    EXTERNAL-IP     PORT(S)
kubernetes   ClusterIP    10.16.0.1     <none>          443/TCP
nginx        LoadBalancer 10.16.4.143   pending         80:32517/TCP
```

这一次，我们使用了一个命令来安装应用程序，同样，您也可以对应用程序进行更改，因为 Kubernetes 足够聪明，它只会更新已更改的资源。

注意

您还可以使用一个命令来显示服务和部署：`kubectl get deployment`/`service`。

我们也可以使用相同的方法来删除应用程序。要使用一个命令删除部署和服务，请运行以下命令：

```
$ kubectl delete –f code/
deployment.apps/nginx deleted
service/nginx deleted
$ kubectl get deployment
No resources found in default namespace.
$ kubectl get service
NAME         TYPE         CLUSTER-IP    EXTERNAL-IP     PORT(S)
kubernetes   ClusterIP    10.16.0.1     <none>          443/TCP
```

如您所见，我们只使用了一个命令来清理所有已安装资源的应用程序。

# 总结

在本章中，我们学习了如何发布新的应用程序版本，回滚应用程序版本，将应用程序分配给特定节点，在不同节点之间调度应用程序副本，并将应用程序暴露到互联网。我们还学习了如何以几种不同的方式删除应用程序。

在下一章中，我们将学习如何调试应用程序，这对于了解应用程序的发布并不总是顺利的情况非常重要。


# 第六章：调试应用程序

有时候，您需要调试应用程序以解决与生产相关的问题。到目前为止，在本书中，我们已经学会了如何安装、更新和删除应用程序。

在本章中，我们将使用`kubectl describe`来进行应用程序调试，以显示解析后的对象配置和期望状态，然后再实际事件发生前检查 pod 日志中的错误，最后，在容器中执行命令（在运行的容器中执行命令意味着在运行的容器中获取 shell 访问）并在那里运行命令。

在本章中，我们将涵盖以下主要主题：

+   描述一个 pod

+   检查 pod 日志

+   在运行的容器中执行命令

# 描述一个 pod

在上一章中，我们删除了一个正在运行的应用程序。因此，在本章中，让我们安装另一个。为了调试应用程序，我们将使用 Docker Hub（[`hub.docker.com/r/bitnami/postgresql`](https://hub.docker.com/r/bitnami/postgresql)）上的`bitnami/postgresql` Docker 镜像，并使用`deployment-postgresql.yaml`文件安装应用程序：

```
$ cat deployment-postgresql.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: postgresql
  labels:
    app: postgresql
spec:
  replicas: 1
  selector:
    matchLabels:
      app: postgresql
  template:
    metadata:
      labels:
        app: postgresql
    spec:
      containers:
      - image: bitnami/postgresql:10.12.10
        imagePullPolicy: IfNotPresent
        name: postgresql
```

要安装 PostgreSQL 部署，请运行以下命令：

```
$ kubectl apply –f deployment-postgresql.yaml
Deployment.apps/postgresql created
$ kubectl get pods
NAME                        READY   STATUS        RESTARTS   AGE
postgresql-867df7d69-r84nl  0/1     ErrImagePull  0          9s
```

哎呀，发生了什么？通过运行`$ kubectl get pods`命令，我们看到了一个`ErrImagePull`错误。让我们来看看。在*第一章*，*介绍和安装 kubectl*中，我们学习了`kubectl describe`命令；让我们使用它来检查 pod 状态。要描述 PostgreSQL pod，请运行以下命令：

```
$ kubectl describe pod postgresql-8675df7d69-r84nl
```

在运行前述命令后，我们得到了以下`Events`的输出：

![图 6.1 - 描述命令的输出](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/kubectl-cli-k8s-nsh/img/B16411_06_001.jpg)

图 6.1 - 描述命令的输出

在前面的截图中，由于`kubectl pod describe`的输出非常大，我们只显示了我们需要检查以解决问题的`Events`部分。

就在这里，我们看到为什么无法拉取镜像：

```
Failed to pull image "bitnami/postgresql:10.12.10": rpc error: code = Unknown desc = Error response from daemon: manifest for bitnami/postgresql:10.12.10 not found: manifest unknown: manifest unknown
```

看着前面的错误，我们可以看到我们引用了错误的标签`postgresql` Docker 镜像。让我们在`deployment-postgresql.yaml`文件中将其更改为`10.13.0`，然后再次运行`kubectl apply`。要更新`postgresql`部署，请运行以下命令：

```
$ kubectl apply –f deployment-postgresql.yaml
Deployment.apps/postgresql configured
$ kubectl get pods
NAME                         READY   STATUS            RESTARTS   AGE
postgresql-56dcb95567-8rdmd  0/1     CrashLoopBackOff  0          36s
postgresql-8675df7d69-r84nl  0/1     ImagePullBackOff  0          35m
```

我们看到了一个新的 pod，`postgresql-56dcb95567-8rdmd`，它也崩溃了。要检查这个`postgresql` pod，请运行以下命令：

```
$ kubectl describe pod postgresql-56dcb95567-8rdmd
```

在运行前述命令后，我们得到了以下输出：

![图 6.2 - 检查带有固定 Docker 标签的 postgresql pod](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/kubectl-cli-k8s-nsh/img/B16411_06_002.jpg)

图 6.2 - 检查带有固定 Docker 标签的 postgresql pod

嗯，这一次，`Events`没有列出关于为什么`postgresql` pod 处于`CrashLoopBackOff`状态的太多信息，因为`bitnami/postgresql:10.13.0`镜像已成功拉取。

让我们在下一节中学习如何处理这个问题，通过检查 pod 的日志。

# 检查 pod 日志

当`kubectl describe pod`没有显示任何关于错误的信息时，我们可以使用另一个`kubectl`命令，即`logs`。`kubectl logs`命令允许我们打印容器日志，并且我们也可以实时查看它们。

提示

如果存在的话，您可以使用带有标志的`kubectl logs`来打印容器在 pod 中的先前实例的日志：

`$ kubectl logs -p some_pod`

现在，让我们在崩溃的`postgresql` pod 上检查这个命令，并尝试找出它失败的原因。要获取 pod 列表并检查 pod 日志，请运行以下命令：

```
$ kubectl get pods
$ kubectl logs postgresql-56dcb95567-njsp6
```

上述命令的输出如下截图所示：

![图 6.3 - 获取 postgresql pod 的错误日志](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/kubectl-cli-k8s-nsh/img/B16411_06_003.jpg)

图 6.3 - 获取 postgresql pod 的错误日志

啊哈！正如您从上面的截图中所看到的，`postgresql` pod 失败了，因为它需要设置`POSTGRESQL_PASSWORD`环境变量为一些密码，或者将`ALLOW_EMPTY_PASSWORD`环境变量设置为`yes`，这将允许容器以空密码启动。

让我们使用一些密码更新`deployment-postgresql.yaml`文件中的`POSTGRESQL_PASSWORD`环境变量设置：

```
$ cat deployment-postgresql.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: postgresql
  labels:
    app: postgresql
spec:
  replicas: 1
  selector:
    matchLabels:
      app: postgresql
  template:
    metadata:
      labels:
        app: postgresql
    spec:
      containers:
      - image: bitnami/postgresql:10.13.0
        imagePullPolicy: IfNotPresent
        name: postgresql
        env:
        - name: POSTGRESQL_PASSWORD
          value: "VerySecurePassword:-)"
```

要更新`postgresql`部署，请运行以下命令：

```
$ kubectl apply –f deployment-postgresql.yaml
Deployment.apps/postgresql configured
$ kubectl get pods
NAME                         READY   STATUS            RESTARTS   AGE
postgresql-56dcb95567-njsp6  0/1     CrashLoopBackOff  11         36m
postgresql-57578b68d9-b6lkv  0/1     ContainerCreating 0          1s
$ kubectl get pods
NAME                         READY   STATUS     RESTARTS   AGE
postgresql-57578b68d9-b6lkv  1/1     Running    0          21s
```

正如您在上面的代码块中所看到的，`postgresql`部署已经更新，成功创建了一个新的 pod，并且崩溃的 pod 已经被终止。

重要提示

最佳实践不建议直接在部署和其他 Kubernetes 模板中存储密码，而是应该将它们存储在 Kubernetes Secrets 中。

现在让我们实时查看`postgresql` pod 日志。要实时检查 pod 日志，请运行以下命令：

```
$ kubectl logs postgresql-57578b68d9-b6lkv -f
```

上述命令的输出如下截图所示：

![图 6.4 - 查看 postgresql 日志](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/kubectl-cli-k8s-nsh/img/B16411_06_004.jpg)

图 6.4 - 查看 postgresql 日志

很好，PostgreSQL 部署已经启动并准备好接受连接。通过保持该命令运行，我们可以在需要查看 PostgreSQL 容器中发生了什么时，实时查看日志。

# 在运行的容器中执行命令

因此，我们已经学会了如何使用`pod describe`和`logs`来排除故障，但在某些情况下，您可能希望进行更高级的故障排除，例如检查一些配置文件或在容器中运行一些命令。这些操作可以使用`kubectl exec`命令完成，该命令将允许`exec`进入容器并在容器中进行交互会话或运行您的命令。

让我们看看如何使用`kubectl exec`命令获取`postgresql.conf`文件的内容：

```
$ kubectl exec postgresql-57578b68d9-6wvpw cat \ /opt/bitnami/postgresql/conf/postgresql.conf
# -----------------------------
# PostgreSQL configuration file
# -----------------------------
#
# This file consists of lines of the form:
#
#   name = value
#
# (The "=" is optional.)  Whitespace may be used.  Comments are introduced with
# "#" anywhere on a line.  The complete list of parameter names and allowed
# values can be found in the PostgreSQL documentation.
…
```

上面的命令将显示`postgresql.conf`文件的内容，以便您可以检查 PostgreSQL 的设置，这些设置在这种情况下是默认设置。

接下来，让我们`exec`进入`postgresql` pod，打开一个 shell，然后运行`psql`命令来检查可用的数据库。

要进入`postgresql` pod，请运行以下命令：

```
$ kubectl exec –it postgresql-57578b68d9-6wvpw – bash
```

上面命令的输出显示在下面的屏幕截图中：

![图 6.5 - 进入 postgresql pod](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/kubectl-cli-k8s-nsh/img/B16411_06_005.jpg)

图 6.5 - 进入 postgresql pod

正如您在上面的屏幕截图中所看到的，我们使用`exec`进入`postgresql` pod，使用`bash` shell，然后运行`psql -Upostgres`登录`postgresql`实例，然后使用`\l`检查可用的数据库。这是一个很好的例子，说明了如何使用交互式`exec`命令并在容器内运行不同的命令。

# 总结

在本章中，我们学习了如何描述 pod，检查日志和故障排除，并且还介绍了如何从头开始为`postgresql` Docker 镜像创建 Kubernetes 部署。

使用`kubectl describe`，`logs`和`exec`的故障排除技能非常有用，可以让您了解应用程序 pod 中发生了什么。这些技术可以帮助您解决遇到的任何问题。

在下一章中，我们将学习如何使用插件扩展`kubectl`。


# 第四部分：扩展 kubectl

本节解释了如何管理 Kubernetes 插件，展示了如何使用 Kustomize 和 Helm，并涵盖了 Docker 用户的命令。

本节包括以下章节：

+   [*第七章*]，*使用 kubectl 插件*

+   [*第八章*]，*介绍 Kustomize 用于 Kubernetes*

+   [*第九章*]，*介绍 Helm 用于 Kubernetes*

+   [*第十章*]，*kubectl 最佳实践和 Docker 命令*


# 第七章：使用 kubectl 插件

在上一章中，我们学习了如何使用`kubectl`进行各种操作，比如列出节点和 pod 以及检查日志。在本章中，让我们学习如何通过插件扩展`kubectl`命令基础。`kubectl`有许多命令，但可能并不总是有你想要的命令，在这种情况下，我们需要使用插件。我们将学习如何安装`kubectl`插件，以便具有更多功能和额外子命令。我们将看到如何使用这些插件，最后，我们将看到如何创建一个`kubectl`的基本插件。

在本章中，我们将涵盖以下主要主题：

+   安装插件

+   使用插件

+   创建基本插件

# 安装插件

在`kubectl`中，插件只是一个可执行文件（可以是编译的 Go 程序或 Bash shell 脚本等），其名称以`kubectl-`开头，要安装插件，只需将其可执行文件放在`PATH`变量中的目录中。

找到并安装插件的最简单方法是使用**Krew** ([`krew.sigs.k8s.io/`](https://krew.sigs.k8s.io/))，Kubernetes 插件管理器。Krew 适用于 macOS、Linux 和 Windows。

Krew 是一个 Kubernetes 插件，让我们继续安装它。在这个例子中，我们将使用 macOS：

1.  要在 macOS 上安装 Krew，请运行`$ brew install krew`命令，如下面的屏幕截图所示：![图 7.1 - 在 macOS 上使用 brew 安装 krew](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/kubectl-cli-k8s-nsh/img/B16411_07_001.jpg)

图 7.1 - 在 macOS 上使用 brew 安装 krew

1.  接下来，我们需要下载插件列表：

```
$ kubectl krew update
```

1.  当我们有一个本地缓存的所有插件列表时，让我们通过运行`$ kubectl krew search`命令来检查可用的插件，如下面的屏幕截图所示：![图 7.2 - 可用插件列表](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/kubectl-cli-k8s-nsh/img/B16411_07_002.jpg)

图 7.2 - 可用插件列表

由于列表中有超过 90 个插件，在前面的屏幕截图中，我们只显示了部分列表。

1.  让我们通过运行`$ kubectl krew install ctx ns view-allocations`命令来安装一些方便的插件，以扩展`kubectl`命令基础，如下面的屏幕截图所示：

![图 7.3 - 使用 Krew 安装插件](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/kubectl-cli-k8s-nsh/img/B16411_07_003.jpg)

图 7.3 - 使用 Krew 安装插件

如你所见，安装`kubectl`插件是如此简单。

# 使用插件

因此，我们已经安装了一些非常有用的插件。让我们看看如何使用它们。

我们已经安装了三个插件：

+   `kubectl ctx`：此插件允许我们在多个 Kubernetes 集群之间轻松切换，当您在`kubeconfig`中设置了多个集群时，这非常有用。

让我们通过运行`$ kubectl ctx`命令来检查可用的集群：

![图 7.4 – ctx 插件](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/kubectl-cli-k8s-nsh/img/B16411_07_004.jpg)

图 7.4 – ctx 插件

+   `kubectl ns`：此插件允许我们在命名空间之间切换。让我们通过运行`$ kubectl ns`命令来检查集群中可用的命名空间：

![图 7.5 – ns 插件](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/kubectl-cli-k8s-nsh/img/B16411_07_005.jpg)

图 7.5 – ns 插件

+   `kubectl view-allocations`：此插件列出命名空间的资源分配，如 CPU、内存、存储等。

让我们通过运行`$ kubectl view-allocations`命令来检查集群中的资源分配：

![图 7.6 – view-allocations 插件](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/kubectl-cli-k8s-nsh/img/B16411_07_006.jpg)

图 7.6 – view-allocations 插件

您可以在上面的列表中看到，使用插件看起来就像这些子命令是`kubectl`工具本身的一部分。

# 创建一个基本插件

在本节中，让我们创建一个名为`toppods`的简单插件来显示 Kubernetes 集群节点。这只是一个创建插件的非常简单的例子：

1.  我们将创建一个名为`kubectl-toppods`的简单基于`bash`的插件：

```
$ cat kubectl-toppods
#!/bin/bash
kubectl top pods
```

1.  让我们将`kubectl-toppods`文件复制到`~/bin`路径：

```
$ cp kubectl-toppods ~/bin
```

1.  确保它是可执行的：

```
$ chmod +x ~/bin/ kubectl-toppods
```

1.  现在让我们尝试运行它：

```
$ kubectl toppods
NAME                        CPU(cores)   MEMORY(bytes)
postgresql-57578b68d9-6rpt8 1m           22Mi
```

不错！您可以看到插件正在工作，而且创建`kubectl`插件并不是很困难。

# 摘要

在本章中，我们已经学会了如何安装、使用和创建`kubectl`插件。了解如何使用现有插件扩展`kubectl`以及如何创建自己的插件是很有用的。

我们已经了解了一些非常方便和有用的`kubectl`插件：

+   `ctx`：允许我们非常轻松地在 Kubernetes 集群之间切换

+   `ns`：允许我们在命名空间之间切换

+   `view-allocations`：显示集群中资源的分配列表

当您每天使用多个 Kubernetes 集群和命名空间时，使用`ctx`和`ns`插件将节省大量时间。

在下一章中，我们将学习如何使用 Kustomize 部署应用程序。


# 第八章：介绍 Kubernetes 的 Kustomize

在上一章中，我们学习了如何安装、使用和创建`kubectl`插件。

在本章中，让我们学习如何在 Kubernetes 中使用 Kustomize。Kustomize 允许我们在不更改应用程序原始模板的情况下修补 Kubernetes 模板。我们将学习 Kustomize 以及如何使用它来修补 Kubernetes 部署。

在本章中，我们将涵盖以下主要主题：

+   Kustomize 简介

+   修补 Kubernetes 部署

# Kustomize 简介

Kustomize 使用 Kubernetes 清单的覆盖来添加、删除或更新配置选项，而无需分叉。Kustomize 的作用是获取 Kubernetes 模板，在`kustomization.yaml`中指定的更改，然后将其部署到 Kubernetes。

这是一个方便的工具，用于修补非复杂的应用程序，例如，需要针对不同环境或资源命名空间的更改。

Kustomize 作为一个独立的二进制文件和自 v.1.14 以来作为`kubectl`中的本机命令可用。

让我们看一下几个 Kustomize 命令，使用以下命令：

+   要在终端上显示生成的修改模板，请使用以下命令：

```
$ kubectl kustomize base 
```

+   要在 Kubernetes 上部署生成的修改模板：

```
$ kubectl apply –k base
```

在前面的示例中，`base`是包含应用程序文件和`kustomization.yaml`的文件夹。

注意

由于没有`base`文件夹，上述命令将失败。这只是命令的示例。

# 修补 Kubernetes 应用程序

在本节中，让我们尝试使用 Kustomize 来修补一个应用程序。例如，我们有一个带有以下文件的`kustomize`文件夹：

![图 8.1 – Kustomize 示例](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/kubectl-cli-k8s-nsh/img/B16411_08_001.jpg)

图 8.1 – Kustomize 示例

`base`文件夹有三个文件—`deployment.yaml`、`service.yaml`和`kustomization.yaml`。

通过运行`$ cat base/deployment.yaml`命令来检查`deployment.yaml`文件：

![图 8.2 – deployment.yaml 文件](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/kubectl-cli-k8s-nsh/img/B16411_08_002.jpg)

图 8.2 – deployment.yaml 文件

在前面的截图中，我们有`nginx`部署模板，我们将在 Kustomize 中使用它。

通过运行`$ cat base/service.yaml`命令来获取`service.yaml`文件的内容：

![图 8.3 – service.yaml 文件](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/kubectl-cli-k8s-nsh/img/B16411_08_003.jpg)

图 8.3 – service.yaml 文件

在前面的截图中，我们有`nginx`服务模板，我们将在 Kustomize 中使用它。

正如您所看到的，我们再次使用了`nginx`部署和服务模板，这样您就更容易理解 Kustomize 的操作。

通过运行`$ cat base/kustomization.yaml`命令，让我们获取`kustomization.yaml.yaml`文件的内容：

![图 8.4 - kustomization.yaml 文件](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/kubectl-cli-k8s-nsh/img/B16411_08_004.jpg)

图 8.4 - kustomization.yaml 文件

由于我们已经熟悉了`nginx`部署和服务，让我们来看看`kustomization.yaml`文件。

通过`kustomization.yaml`中的以下代码，我们为`nginx`图像设置了一个新标签：

```
```

图像：

- 名称：nginx

newTag: 1.19.1

```
```

以下代码设置了要应用设置的`resources`。由于`service`没有图像，Kustomize 只会应用于`deployment`，但我们将在以后的步骤中需要`service`，所以我们仍然设置它：

```
```

资源：

- deployment.yaml

- service.yaml

```
```

现在，让我们通过运行`$ kubectl kustomize base`命令来检查 Kustomize 将如何更改部署：

![图 8.5 - kubectl kustomize base 输出](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/kubectl-cli-k8s-nsh/img/B16411_08_005.jpg)

图 8.5 - kubectl kustomize base 输出

从前面的输出中，您可以看到 Kustomize 生成了`service`和`deployment`内容。`service`的内容没有改变，但让我们来看看`deployment`。将原始文件`base/deployment.yaml`与前面的输出进行比较，我们看到`- image: nginx:1.18.0`已更改为`- image: nginx:1.19.1`，正如在`kustomization.yaml`文件中指定的那样。

这是一个很好且简单的`image`标签更改，而不需要修改原始的`deployment.yaml`文件。

注意

这样的技巧特别方便，特别是在真实的应用程序部署中，不同的环境可能使用不同的 Docker 镜像标签。

## Kustomize 叠加

作为系统管理员，我希望能够部署具有专用自定义配置的不同环境（开发和生产）的 Web 服务，例如副本的数量，分配的资源，安全规则或其他配置。我希望能够在不维护核心应用程序配置的重复副本的情况下完成这些操作。

在本节中，让我们通过使用 Kustomize 进行更高级的自定义来部署到开发和生产环境，并为每个环境使用不同的命名空间和 NGINX Docker 标签来学习更多内容。

在`overlays`文件夹中，我们有`development/kustomization.yaml`和`production/kustomization.yaml`文件；让我们来检查它们。在下面的截图中，我们有`kustomization.yaml`文件，它将应用于开发环境。

通过运行`$ cat overlays/development/kustomization.yaml`命令来获取`overlays/development/kustomization.yaml`文件的内容：

![图 8.6 - development/kustomization.yaml 内容](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/kubectl-cli-k8s-nsh/img/B16411_08_006.jpg)

图 8.6 - development/kustomization.yaml 内容

在上述截图中，我们有`kustomization.yaml`文件，它将应用于开发环境。

通过运行`$ cat overlays/development/kustomization.yaml`命令来获取`overlays/production/kustomization.yaml`文件的内容：

![图 8.7 - production/kustomization.yaml 内容](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/kubectl-cli-k8s-nsh/img/B16411_08_007.jpg)

图 8.7 - production/kustomization.yaml 内容

在上述截图中，我们有`kustomization.yaml`文件，它将应用于生产环境。

好的，让我们来检查我们在`development/kustomization.yaml`文件中得到的更改：

```
resources:
- ../../base # setting where the main templates are stored
nameSuffix: -development # updating service/deployment name
commonLabels:
  environment: development # add new label
namespace: nginx-dev # setting namespace
```

让我们通过运行`$ kubectl kustomize overlays/development`命令来看看这些更改将如何应用于开发环境的`deployment`和`service`：

![图 8.8 - kubectl kustomize overlays/development 输出](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/kubectl-cli-k8s-nsh/img/B16411_08_008.jpg)

图 8.8 - kubectl kustomize overlays/development 输出

根据`base`文件夹规范，我们可以看到`deployment`和`service`的名称已更改，添加了一个命名空间，并且`nginx`镜像标签也已更改。到目前为止做得很好！

现在让我们检查`production/kustomization.yaml`文件：

```
resources:
- ../../base # setting where the main templates are stored
nameSuffix: -production # updating service/deployment name
commonLabels:
  environment: production # add new label
namespace: nginx-prod # setting namespace
images:
- name: nginx
  newTag: 1.19.2 # tag gets changed
```

我们要应用的更改与为`development`所做的更改非常相似，但我们还希望设置不同的 Docker 镜像标签。

通过运行`$ kubectl kustomize overlays/production`命令来看看它将如何运行：

![图 8.9 - kubectl kustomize overlays/production 输出](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/kubectl-cli-k8s-nsh/img/B16411_08_009.jpg)

图 8.9 - kubectl kustomize overlays/production 输出

正如你所看到的，所有所需的更改都已应用。

注意

Kustomize 合并所有找到的`kustomization.yaml`文件，首先应用来自`base`文件夹的文件，然后应用来自`overlay`文件夹的文件。您可以选择如何命名您的文件夹。

现在，是时候实际执行使用 Kustomize 进行安装了：

```
$ kubectl create ns nginx-prod 
namespace/nginx-prod created
$ kubectl apply –k overlays/production/
service/nginx-prod created
deployment.apps/nginx-production created
$ kubectl get pods –n nginx-prod
NAME                    READY   STATUS    RESTARTS   AGE
nginx-production-dc9cbdb6-j4ws4   1/1     Running   0          17s
```

通过上述命令，我们已经创建了`nginx-prod`命名空间，并借助 Kustomize 应用的更改安装了`nginx`应用程序，您可以看到它正在运行。

我们只学习了 Kustomize 的一些基本功能，因为在本书中涵盖 Kustomize 的所有内容超出了范围，请参考以下链接获取更多信息：[`kustomize.io/`](https://kustomize.io/)。

# 总结

在本章中，我们学会了如何使用 Kustomize 安装应用程序。

我们已经学会了如何将 Kustomize 应用于`nginx`部署和服务，改变它们的名称，添加命名空间，并在部署中更改镜像标签。所有这些都是在不更改应用程序原始模板的情况下完成的，通过使用带有 Kustomize 的`kustomization.yaml`文件来进行所需的更改。

在下一章中，我们将学习如何使用 Helm——Kubernetes 软件包管理器。
