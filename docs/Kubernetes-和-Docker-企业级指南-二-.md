# Kubernetes 和 Docker 企业级指南（二）

> 原文：[`zh.annas-archive.org/md5/9023162EFAC3D4D142381E2C55E3B624`](https://zh.annas-archive.org/md5/9023162EFAC3D4D142381E2C55E3B624)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：Kubernetes 训练营

我们相信你们中的许多人在某种程度上使用过 Kubernetes——您可能在生产环境中运行集群，或者您可能使用过 kubeadm、Minikube 或 Docker Desktop 进行试验。我们的目标是超越 Kubernetes 的基础知识，因此我们不想重复 Kubernetes 的所有基础知识。相反，我们添加了这一章作为一个训练营，供那些可能对 Kubernetes 还不熟悉，或者可能只是稍微玩过一下的人参考。

由于这是一个训练营章节，我们不会深入讨论每个主题，但到最后，您应该对 Kubernetes 的基础知识有足够的了解，以理解剩下的章节。如果您对 Kubernetes 有很强的背景，您可能仍然会发现本章对您有用，因为它可以作为一个复习，我们将在第六章《服务、负载均衡和外部 DNS》开始讨论更复杂的主题。

在这一章中，我们将介绍运行中的 Kubernetes 集群的组件，包括控制平面和工作节点。我们将详细介绍每个 Kubernetes 对象及其用例。如果您以前使用过 Kubernetes，并且熟悉使用 kubectl 并完全了解 Kubernetes 对象（如 DaemonSets，StatefulSets，ReplicaSets 等），您可能希望跳转到第六章《服务、负载均衡和外部 DNS》，在那里我们将使用 KinD 安装 Kubernetes。

在本章中，我们将涵盖以下主题：

+   Kubernetes 组件概述

+   探索控制平面

+   了解工作节点组件

+   与 API 服务器交互

+   介绍 Kubernetes 对象

# 技术要求

本章有以下技术要求：

+   具有至少 4GB 随机存取内存（RAM）的 Ubuntu 18.04 服务器

+   一个 KinD Kubernetes 集群

您可以在以下 GitHub 存储库中访问本章的代码：[`github.com/PacktPublishing/Kubernetes-and-Docker-The-Complete-Guide`](https://github.com/PacktPublishing/Kubernetes-and-Docker-The-Complete-Guide)。

# Kubernetes 组件概述

在任何基础设施中，了解系统如何共同提供服务总是一个好主意。如今有这么多安装选项，许多 Kubernetes 用户并不需要了解 Kubernetes 组件如何集成。

短短几年前，如果您想运行一个 Kubernetes 集群，您需要手动安装和配置每个组件。安装一个运行的集群是一个陡峭的学习曲线，经常导致挫折，让许多人和公司说“Kubernetes 太难了”。手动安装的优势在于，您真正了解每个组件是如何交互的，如果安装后您的集群遇到问题，您知道要查找什么。

如今，大多数人会在云服务提供商上点击一个按钮，几分钟内就可以拥有一个完全运行的 Kubernetes 集群。本地安装也变得同样简单，谷歌、红帽、牧场等提供了选项，消除了安装 Kubernetes 集群的复杂性。我们看到的问题是，当安装后遇到问题或有疑问时。由于您没有配置 Kubernetes 组件，您可能无法向开发人员解释 Pod 是如何在工作节点上调度的。最后，由于您正在运行第三方提供的安装程序，他们可能启用或禁用您不知道的功能，导致安装可能违反您公司的安全标准。

要了解 Kubernetes 组件如何协同工作，首先必须了解 Kubernetes 集群的不同组件。以下图表来自**Kubernetes.io**网站，显示了 Kubernetes 集群组件的高级概述：

![图 5.1 - Kubernetes 集群组件](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/k8s-dkr/img/Fig_5.1_B15514.jpg)

图 5.1 - Kubernetes 集群组件

正如您所看到的，Kubernetes 集群由多个组件组成。随着我们在本章中的进展，我们将讨论这些组件及它们在 Kubernetes 集群中的作用。

# 探索控制平面

顾名思义，控制平面控制集群的每个方面。如果您的控制平面崩溃，您可能可以想象到您的集群将遇到问题。没有控制平面，集群将没有任何调度能力，这意味着正在运行的工作负载将保持运行，除非它们被停止和重新启动。由于控制平面非常重要，因此建议您至少有三个主节点。许多生产安装运行超过三个主节点，但安装节点的数量应始终是奇数。让我们看看为什么控制平面及其组件对运行中的集群如此重要，通过检查每个组件。

## Kubernetes API 服务器

在集群中要理解的第一个组件是**kube-apiserver**组件。由于 Kubernetes 是**应用程序编程接口**（**API**）驱动的，进入集群的每个请求都经过 API 服务器。让我们看一个简单的使用 API 端点的**获取节点**请求，如下所示：

**https://10.240.100.100:6443/api/v1/nodes?limit=500**

Kubernetes 用户常用的一种与 API 服务器交互的方法是 kubectl 实用程序。使用 kubectl 发出的每个命令在幕后调用一个 API 端点。在前面的示例中，我们执行了一个**kubectl get nodes**命令，该命令将一个 API 请求发送到端口**6443**上的**10.240.100.100**上的**kube-apiserver**进程。API 调用请求了**/api/vi/nodes**端点，返回了集群中节点的列表，如下截图所示：

![图 5.2 - Kubernetes 节点列表](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/k8s-dkr/img/Fig_5.2_B15514.jpg)

图 5.2 - Kubernetes 节点列表

没有运行的 API 服务器，集群中的所有请求都将失败。因此，可以看到，始终运行**kube-apiserver**组件非常重要。通过运行三个或更多的主节点，我们可以限制失去主节点的任何影响。

注意

当运行多个主节点时，您需要在集群前面放置一个负载均衡器。Kubernetes API 服务器可以由大多数标准解决方案，包括 F5、HAProxy 和 Seesaw。

## Etcd 数据库

毫不夸张地说，Etcd 就是您的 Kubernetes 集群。Etcd 是一个快速且高可用的分布式键值数据库，Kubernetes 使用它来存储所有集群数据。集群中的每个资源在数据库中都有一个键。如果您登录到运行 Etcd 的节点或 Pod，您可以使用**etcdctl**可执行文件查看数据库中的所有键。以下代码片段显示了运行 KinD 集群的示例：

EtcdCTL_API=3 etcdctl --endpoints=https://127.0.0.1:2379 --cacert=/etc/kubernetes/pki/etcd/ca.crt --key=/etc/kubernetes/pki/etcd/server.key --cert=/etc/kubernetes/pki/etcd/server.crt get / --prefix --keys-only

前面命令的输出包含太多数据，无法在本章中列出。基本的 KinD 集群将返回大约 317 个条目。所有键都以**/registry/<object>**开头。例如，返回的键之一是**cluster-admin**键的**ClusterRole**，如下所示：**/registry/clusterrolebindings/cluster-admin**。

我们可以使用键名使用**etcdctl**实用程序检索值，稍微修改我们之前的命令，如下所示：

EtcdCTL_API=3 etcdctl --endpoints=https://127.0.0.1:2379 --cacert=/etc/kubernetes/pki/etcd/ca.crt --key=/etc/kubernetes/pki/etcd/server.key --cert=/etc/kubernetes/pki/etcd/server.crt get /registry/clusterrolebindings/cluster-admin

输出将包含您的 shell 无法解释的字符，但您将了解存储在 Etcd 中的数据。对于**cluster-admin**键，输出显示如下：

！[](image/Fig_5.3_B15514.jpg)

图 5.3 - etcdctl ClusterRoleBinding 输出

我们解释 Etcd 中的条目是为了提供 Kubernetes 如何使用它来运行集群的背景。您已经从数据库直接查看了**cluster-admin**键的输出，但在日常生活中，您将使用**kubectl get clusterrolebinding cluster-admin -o yaml**查询 API 服务器，它将返回以下内容：

！[](image/Fig_5.4_B15514.jpg)

图 5.4 - kubectl ClusterRoleBinding 输出

如果您查看**kubectl**命令的输出并将其与**etcdctl**查询的输出进行比较，您将看到匹配的信息。当您执行**kubectl**命令时，请求将发送到 API 服务器，然后 API 服务器将查询 Etcd 数据库以获取对象的信息。

## kube-scheduler

正如其名称所示，**kube-scheduler**组件负责调度运行中的 Pod。每当集群中启动一个 Pod 时，API 服务器会接收请求，并根据多个标准（包括主机资源和集群策略）决定在哪里运行工作负载。

## kube-controller-manager

**kube-controller-manager**组件实际上是一个包含多个控制器的集合，包含在一个单一的二进制文件中。将四个控制器包含在一个可执行文件中可以通过在单个进程中运行所有四个来减少复杂性。**kube-controller-manager**组件中包含的四个控制器是节点、复制、端点以及服务账户和令牌控制器。

每个控制器为集群提供独特的功能，每个控制器及其功能在此列出：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/k8s-dkr/img/B15514_table_5.1.jpg)

每个控制器都运行一个非终止的控制循环。这些控制循环监视每个资源的状态，进行任何必要的更改以使资源的状态正常化。例如，如果您需要将一个部署从一个节点扩展到三个节点，复制控制器会注意到当前状态有一个 Pod 正在运行，期望状态是有三个 Pod 正在运行。为了将当前状态移动到期望状态，复制控制器将请求另外两个 Pod。

## cloud-controller-manager

这是一个您可能没有遇到的组件，这取决于您的集群如何配置。与**kube-controller-manager**组件类似，这个控制器在一个单一的二进制文件中包含了四个控制器。包含的控制器是节点、路由、服务和卷控制器，每个控制器负责与其各自的云服务提供商进行交互。

# 了解工作节点组件

工作节点负责运行工作负载，正如其名称所示。当我们讨论控制平面的**kube-scheduler**组件时，我们提到当新的 Pod 被调度时，**kube-scheduler**组件将决定在哪个节点上运行 Pod。它使用来自工作节点的信息来做出决定。这些信息不断更新，以帮助在集群中分配 Pod 以有效利用资源。以下是工作节点组件的列表。

## kubelet

您可能会听到将工作节点称为**kubelet**。**kubelet**是在所有工作节点上运行的代理，负责运行实际的容器。

## kube-proxy

与名称相反，**kube-proxy**根本不是代理服务器。**kube-proxy**负责在 Pod 和外部网络之间路由网络通信。

## 容器运行时

这在图片中没有体现，但每个节点也需要一个容器运行时。容器运行时负责运行容器。您可能首先想到的是 Docker。虽然 Docker 是一个容器运行时，但它并不是唯一的运行时选项。在过去的一年里，其他选项已经可用，并且正在迅速取代 Docker 成为首选的容器运行时。最突出的两个 Docker 替代品是 CRI-O 和 containerd。

在书的练习中，我们将使用 KinD 创建一个 Kubernetes 集群。在撰写本文时，KinD 只提供对 Docker 作为容器运行时的官方支持，并对 Podman 提供有限支持。

# 与 API 服务器交互

正如我们之前提到的，您可以使用直接的 API 请求或**kubectl**实用程序与 API 服务器进行交互。在本书中，我们将重点介绍使用**kubectl**进行大部分交互，但在适当的情况下，我们将介绍使用直接的 API 调用。

## 使用 Kubernetes kubectl 实用程序

**kubectl**是一个单个可执行文件，允许您使用**命令行界面**（**CLI**）与 Kubernetes API 进行交互。它适用于大多数主要操作系统和架构，包括 Linux、Windows 和 Mac。

大多数操作系统的安装说明位于 Kubernetes 网站的[`kubernetes.io/docs/tasks/tools/install-kubectl/`](https://kubernetes.io/docs/tasks/tools/install-kubectl/)。由于我们在书中的练习中使用 Linux 作为操作系统，我们将介绍在 Linux 机器上安装**kubectl**的步骤：

1.  要下载**kubectl**的最新版本，您可以运行一个**curl**命令来下载它，如下所示：

**curl -LO https://storage.googleapis.com/kubernetes-release/release/`curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt`/bin/linux/amd64/kubectl**

1.  下载后，您需要通过运行以下命令使文件可执行：

**chmod +x ./kubectl**

1.  最后，我们将将可执行文件移动到您的路径，如下所示：

**sudo mv ./kubectl /usr/local/bin/kubectl**

您现在在系统上拥有最新的 **kubectl** 实用程序，并且可以从任何工作目录执行 **kubectl** 命令。

Kubernetes 每 3 个月更新一次。这包括对基本 Kubernetes 集群组件和 **kubectl** 实用程序的升级。您可能会遇到集群和 **kubectl** 命令之间的版本不匹配，需要您升级或下载 **kubectl** 可执行文件。您可以通过运行 **kubectl version** 命令来随时检查两者的版本，该命令将输出 API 服务器和 **kubectl** 客户端的版本。版本检查的输出如下代码片段所示：

客户端版本：version.Info{Major:"1", Minor:"17", GitVersion:"v1.17.1", GitCommit:"d224476cd0730baca2b6e357d144171ed74192d6", GitTreeState:"clean", BuildDate:"2020-01-14T21:04:32Z", GoVersion:"go1.13.5", Compiler:"gc", Platform:"linux/amd64"}

服务器版本：version.Info{Major:"1", Minor:"17", GitVersion:"v1.17.0", GitCommit:"70132b0f130acc0bed193d9ba59dd186f0e634cf", GitTreeState:"clean", BuildDate:"2020-01-14T00:09:19Z", GoVersion:"go1.13.4", Compiler:"gc", Platform:"linux/amd64"}

从输出中可以看出，**kubectl** 客户端正在运行版本 **1.17.1**，而集群正在运行 **1.17.0**。两者之间的次要版本差异不会引起任何问题。事实上，官方支持的版本差异在一个主要版本发布之内。因此，如果您的客户端运行的是版本 1.16，而集群运行的是 1.17，您将在支持的版本差异范围内。虽然这可能得到支持，但这并不意味着如果您尝试使用高版本中包含的任何新命令或对象，就不会遇到问题。通常情况下，您应该尽量保持集群和客户端版本同步，以避免任何问题。

在本章的其余部分，我们将讨论 Kubernetes 对象以及您如何与 API 服务器交互来管理每个对象。但在深入讨论不同对象之前，我们想提到 **kubectl** 实用程序的一个常被忽视的选项：**verbose** 选项。

## 理解 verbose 选项

当您执行**kubectl**命令时，默认情况下您只会看到对您的命令的任何直接响应。如果您要查看**kube-system**命名空间中的所有 Pod，您将收到所有 Pod 的列表。在大多数情况下，这是期望的输出，但是如果您发出**get Pods**请求并从 API 服务器收到错误，该怎么办？您如何获取有关可能导致错误的更多信息？

通过将**冗长**选项添加到您的**kubectl**命令中，您可以获得有关 API 调用本身以及来自 API 服务器的任何回复的额外详细信息。通常，来自 API 服务器的回复将包含可能有助于找到问题根本原因的额外信息。

**冗长**选项有多个级别，从 0 到 9 不等；数字越高，输出越多。以下截图来自 Kubernetes 网站，详细说明了每个级别和输出内容：

![图 5.5 - 冗长描述](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/k8s-dkr/img/Fig_5.5_B15514.jpg)

图 5.5 - 冗长描述

您可以通过向任何**kubectl**命令添加**-v**或**--v**选项来尝试不同级别。

## 常规 kubectl 命令

CLI 允许您以命令式和声明式方式与 Kubernetes 进行交互。使用命令式命令涉及告诉 Kubernetes 要做什么-例如，**kubectl run nginx –image nginx**。这告诉 API 服务器创建一个名为**nginx**的新部署，运行一个名为**nginx**的镜像。虽然命令式命令对开发和快速修复或测试很有用，但在生产环境中，您将更频繁地使用声明式命令。在声明式命令中，您告诉 Kubernetes 您想要什么。要使用声明式命令，您将一个通常用**YAML Ain't Markup Language**（**YAML**）编写的清单发送到 API 服务器，声明您要 Kubernetes 创建什么。

**kubectl**包括可以提供一般集群信息或对象信息的命令和选项。以下表格包含了命令的速查表以及它们的用途。我们将在未来的章节中使用许多这些命令，因此您将在整本书中看到它们的实际应用：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/k8s-dkr/img/B15514_table_5.2.jpg)

通过了解每个 Kubernetes 组件以及如何使用命令与 API 服务器进行交互，我们现在可以继续学习 Kubernetes 对象以及如何使用**kubectl**来管理它们。

# 介绍 Kubernetes 对象

本节将包含大量信息，由于这是一个训练营，我们不会深入讨论每个对象的细节。正如您可以想象的那样，每个对象都可能在一本书中有自己的章节，甚至多个章节。由于有许多关于 Kubernetes 的书籍详细介绍了基本对象，我们只会涵盖每个对象的必要细节，以便了解每个对象。在接下来的章节中，我们将在构建集群时包含对象的附加细节。

在我们继续了解 Kubernetes 对象的真正含义之前，让我们首先解释一下 Kubernetes 清单。

## Kubernetes 清单

我们将用来创建 Kubernetes 对象的文件称为清单。清单可以使用 YAML 或**JavaScript 对象表示法**（**JSON**）创建——大多数清单使用 YAML，这也是我们在整本书中将使用的格式。

清单的内容将根据将要创建的对象或对象而变化。至少，所有清单都需要包含**apiVersion**、对象**KinD**和**metadata**字段的基本配置，如下所示：

apiVersion：apps/v1

KinD：部署

元数据：

标签：

应用：grafana

名称：grafana

命名空间：监控

前面的清单本身并不完整；我们只是展示了完整部署清单的开头。正如您在文件中所看到的，我们从所有清单都必须具有的三个必需字段开始：**apiVersion**、**KinD**和**metadata**字段。

您可能还注意到文件中有空格。YAML 非常具体格式，如果任何行的格式偏离了一个空格，您在尝试部署清单时将收到错误。这需要时间来适应，即使创建清单已经很长时间，格式问题仍然会不时出现。

## Kubernetes 对象是什么？

当您想要向集群添加或删除某些内容时，您正在与 Kubernetes 对象进行交互。对象是集群用来保持所需状态列表的东西。所需状态可能是创建、删除或扩展对象。根据对象的所需状态，API 服务器将确保当前状态等于所需状态。

检索集群支持的对象列表，可以使用**kubectl api-resources**命令。API 服务器将回复一个包含所有对象的列表，包括任何有效的简称、命名空间支持和支持的 API 组。基本集群包括大约 53 个基本对象，但以下截图显示了最常见对象的缩略列表：

![图 5.6 - Kubernetes API 资源](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/k8s-dkr/img/Fig_5.6_B15514.jpg)

图 5.6 - Kubernetes API 资源

由于本章是一个训练营，我们将简要回顾列表中的许多对象。为了确保您能够跟随剩余的章节，我们将提供每个对象的概述以及如何与它们交互的概述。一些对象也将在未来的章节中更详细地解释，包括**Ingress**、**RoleBindings**、**ClusterRoles**、**StorageClasses**等等。

## 审查 Kubernetes 对象

为了使本节更容易理解，我们将按照**kubectl api-services**命令提供的顺序呈现每个对象。

集群中的大多数对象都在命名空间中运行，要创建/编辑/读取它们，您应该向任何**kubectl**命令提供**-n <namespace>**选项。要查找接受命名空间选项的对象列表，可以参考我们之前**get api-server**命令的输出。如果对象可以由命名空间引用，命名空间列将显示**true**。如果对象只能由集群级别引用，命名空间列将显示**false**。

### ConfigMaps

ConfigMap 以键值对的形式存储数据，提供了一种将配置与应用程序分开的方法。ConfigMaps 可以包含来自文字值、文件或目录的数据。

这是一个命令式的例子：

kubectl create configmap <name> <data>

**name**选项将根据 ConfigMap 的来源而变化。要使用文件或目录，您需要提供**--from-file**选项和文件路径或整个目录，如下所示：

kubectl create configmap config-test --from-file=/apps/nginx-config/nginx.conf

这将创建一个名为**config-test**的新 ConfigMap，其中**nginx.conf**键包含**nginx.conf**文件的内容作为值。

如果您需要在单个 ConfigMap 中添加多个键，可以将每个文件放入一个目录中，并使用目录中的所有文件创建 ConfigMap。例如，您在位于**~/config/myapp**的目录中有三个文件，每个文件都包含数据，分别称为**config1**，**config2**和**config3**。要创建一个 ConfigMap，将每个文件添加到一个键中，您需要提供**--from-file**选项并指向该目录，如下所示：

kubectl create configmap config-test --from-file=/apps/config/myapp

这将创建一个新的**ConfigMap**，其中包含三个键值，分别称为**config1**，**config2**和**config3**。每个键将包含与目录中每个文件内容相等的值。

为了快速显示一个**ConfigMap**，使用从目录创建**ConfigMap**的示例，我们可以使用 get 命令检索**ConfigMap**，**kubectl get configmaps config-test**，得到以下输出：

名称 数据 年龄 config-test 3 7s

我们可以看到 ConfigMap 包含三个键，显示为**DATA**列下的**3**。为了更详细地查看，我们可以使用相同的**get**命令，并通过将**-o yaml**选项添加到**kubectl get configmaps config-test -o yaml**命令来输出每个键的值作为 YAML，得到以下输出：

![图 5.7 - kubectl ConfigMap 输出](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/k8s-dkr/img/Fig_5.7_B15514.jpg)

图 5.7 - kubectl ConfigMap 输出

从前面的输出中可以看到，每个键都与文件名匹配，每个键的值都包含各自文件中的数据。

您应该记住 ConfigMaps 的一个限制是，数据对于具有对象权限的任何人都很容易访问。正如您从前面的输出中所看到的，一个简单的**get**命令显示了明文数据。由于这种设计，您不应该在 ConfigMap 中存储诸如密码之类的敏感信息。在本节的后面，我们将介绍一个专门设计用于存储敏感信息的对象，称为 Secret。

### 终端

端点将服务映射到一个 Pod 或多个 Pod。当我们解释**Service**对象时，这将更有意义。现在，您只需要知道您可以使用 CLI 通过使用**kubectl get endpoints**命令来检索端点。在一个新的 KinD 集群中，您将在默认命名空间中看到 Kubernetes API 服务器的值，如下面的代码片段所示：

命名空间 名称 终端 年龄

默认 kubernetes 172.17.0.2:6443 22 小时

输出显示集群有一个名为**kubernetes**的服务，在**Internet Protocol**（**IP**）地址**172.17.0.2**的端口**6443**上有一个端点。稍后，当查看端点时，您将看到它们可用于解决服务和入口问题。

### 事件

**事件**对象将显示命名空间的任何事件。要获取**kube-system**命名空间的事件列表，您将使用**kubectl get events -n kube-system**命令。

### 命名空间

命名空间是将集群划分为逻辑单元的对象。每个命名空间允许对资源进行细粒度管理，包括权限、配额和报告。

**命名空间**对象用于命名空间任务，这些任务是集群级别的操作。使用**命名空间**对象，您可以执行包括**创建**、**删除**、**编辑**和**获取**在内的命令。

该命令的语法是**kubectl <动词> ns <命名空间名称>**。

例如，要描述**kube-system**命名空间，我们将执行**kubectl describe namespaces kube-system**命令。这将返回命名空间的信息，包括任何标签、注释和分配的配额，如下面的代码片段所示：

名称：kube-system

标签：<无>注释：<无>

状态：活动

没有资源配额。

没有 LimitRange 资源。

在上述输出中，您可以看到该命名空间没有分配任何标签、注释或资源配额。

此部分仅旨在介绍命名空间作为多租户集群中的管理单元的概念。如果您计划运行具有多个租户的集群，您需要了解如何使用命名空间来保护集群。

### 节点

**节点**对象是用于与集群节点交互的集群级资源。此对象可用于各种操作，包括**获取**、**描述**、**标签**和**注释**。

要使用**kubectl**检索集群中所有节点的列表，您需要执行**kubectl get nodes**命令。在运行简单单节点集群的新 KinD 集群上，显示如下：

名称 状态 角色 年龄 版本

KinD-control-plane 就绪 主节点 22 小时 v1.17.0

您还可以使用 nodes 对象使用**describe**命令获取单个节点的详细信息。要获取先前列出的 KinD 节点的描述，我们可以执行**kubectl describe node KinD-control-plane**，这将返回有关节点的详细信息，包括消耗的资源、运行的 Pods、IP **无类域间路由**（**CIDR**）范围等。

### 持久卷索赔

我们将在后面的章节中更深入地描述**持久卷索赔**（**PVCs**），但现在您只需要知道 PVC 用于 Pod 消耗持久存储。PVC 使用**持久卷**（**PV**）来映射存储资源。与我们讨论过的大多数其他对象一样，您可以对 PVC 对象发出**get**、**describe**和**delete**命令。由于它们被 Pods 使用，它们是一个**命名空间**对象，并且必须在与将使用 PVC 的 Pod 相同的命名空间中创建。

### 持久卷

PVs 被 PVCs 使用，以在 PVC 和底层存储系统之间创建链接。手动维护 PVs 是一项混乱的任务，在现实世界中应该避免，因为 Kubernetes 包括使用**容器存储接口**（**CSI**）管理大多数常见存储系统的能力。正如在**PVC**对象部分提到的，我们将讨论 Kubernetes 如何自动创建将与 PVCs 链接的 PVs。

### Pods

Pod 对象用于与运行您的容器的 Pod 进行交互。使用**kubectl**实用程序，您可以使用**get**、**delete**和**describe**等命令。例如，如果您想要获取**kube-system**命名空间中所有 Pods 的列表，您将执行一个**kubectl get Pods -n kube-system**命令，该命令将返回命名空间中的所有 Pods，如下所示：

![图 5.8 - kube-system 命名空间中的所有 Pods](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/k8s-dkr/img/Fig_5.8_B15514.jpg)

图 5.8 - kube-system 命名空间中的所有 Pods

虽然您可以直接创建一个 Pod，但除非您正在使用 Pod 进行快速故障排除，否则应避免这样做。直接创建的 Pod 无法使用 Kubernetes 提供的许多功能，包括扩展、自动重启或滚动升级。您应该使用部署，或在一些罕见情况下使用**ReplicaSet**对象或复制控制器，而不是直接创建 Pod。

### 复制控制器

复制控制器将管理运行中的 Pod 的数量，始终保持指定数量的副本运行。如果创建一个复制控制器并将副本计数设置为**5**，则控制器将始终保持应用程序的五个 Pod 运行。

复制控制器已被**ReplicaSet**对象取代，我们将在其专门部分讨论。虽然您仍然可以使用复制控制器，但应考虑使用部署或**ReplicaSet**对象。

### 资源配额

在多个团队之间共享 Kubernetes 集群变得非常普遍，称为多租户集群。由于您将在单个集群中有多个团队工作，因此应考虑创建配额，以限制单个租户在集群或节点上消耗所有资源的潜力。可以对大多数集群对象设置限制，包括以下内容：

+   中央处理器（CPU）

+   内存

+   PVC

+   配置映射

+   部署

+   Pod 和更多

设置限制将在达到限制后阻止创建任何其他对象。如果为命名空间设置了 10 个 Pod 的限制，并且用户创建了一个尝试启动 11 个 Pod 的新部署，则第 11 个 Pod 将无法启动，并且用户将收到错误。

创建内存和 CPU 配额的基本清单文件将如下所示：

apiVersion：v1

KinD：ResourceQuota

元数据：

名称：base-memory-cpu

规范：

硬：

requests.cpu："2"

requests.memory：8Gi

limits.cpu："4"

limits.memory：16Gi

这将限制命名空间可以用于 CPU 和内存请求和限制的总资源量。

创建配额后，您可以使用**kubectl describe**命令查看使用情况。在我们的示例中，我们将**ResourceQuota**命名为**base-memory-cpu**。要查看使用情况，我们将执行**kubectl get resourcequotas base-memory-cpu**命令，结果如下：

名称：base-memory-cpu

命名空间：默认

已使用的资源硬件

-------- ---- ----

limits.cpu 0 4

limits.memory 0 16Gi

requests.cpu 0 2

requests.memory 0 8Gi

**ResourceQuota**对象用于控制集群的资源。通过为命名空间分配资源，您可以保证单个租户将拥有运行其应用程序所需的 CPU 和内存，同时限制糟糕编写的应用程序可能对其他应用程序造成的影响。

### 秘密

我们之前描述了如何使用**ConfigMap**对象存储配置信息。我们提到**ConfigMap**对象不应该用于存储任何类型的敏感数据。这是 Secret 的工作。

Secrets 以 Base64 编码的字符串形式存储，这不是一种加密形式。那么，为什么要将 Secrets 与**ConfigMap**对象分开呢？提供一个单独的对象类型可以更容易地维护访问控制，并且可以使用外部系统注入敏感信息。

Secrets 可以使用文件、目录或文字字符串创建。例如，我们有一个要执行的 MySQL 镜像，并且我们希望使用 Secret 将密码传递给 Pod。在我们的工作站上，我们有一个名为**dbpwd**的文件，其中包含我们的密码。使用**kubectl**命令，我们可以通过执行**kubectl create secret generic mysql-admin --from-file=./dbpwd**来创建一个 Secret。

这将在当前命名空间中创建一个名为**mysql-admin**的新 Secret，其中包含**dbpwd**文件的内容。使用**kubectl**，我们可以通过运行**kubectl get secret mysql-admin -o yaml**命令来获取 Secret 的输出，该命令将输出以下内容：

apiVersion: v1

data:

dbpwd: c3VwZXJzZWNyZXQtcGFzc3dvcmQK

KinD: Secret

metadata:

creationTimestamp: "2020-03-24T18:39:31Z"

name: mysql-admin

namespace: default

resourceVersion: "464059"

selfLink: /api/v1/namespaces/default/secrets/mysql-admin

uid: 69220ebd-c9fe-4688-829b-242ffc9e94fc

type: Opaque

从前面的输出中，您可以看到**data**部分包含我们文件的名称，然后是从文件内容创建的 Base64 编码值。

如果我们从 Secret 中复制 Base64 值并将其传输到**base64**实用程序，我们可以轻松解码密码，如下所示：

echo c3VwZXJzZWNyZXQtcGFzc3dvcmQK | base64 -d

supersecret-password

提示

在使用**echo**命令对字符串进行 Base64 编码时，添加**-n**标志以避免添加额外的**\n**。而不是**echo 'test' | base64**，使用**echo -n 'test' | base64**。

所有内容都存储在 Etcd 中，但我们担心有人可能能够入侵主服务器并窃取 Etcd 数据库的副本。一旦有人拿到数据库的副本，他们可以轻松使用**etcdctl**实用程序浏览内容以检索我们所有的 Base64 编码的 Secrets。幸运的是，Kubernetes 添加了一个功能，可以在将 Secrets 写入数据库时对其进行加密。

对许多用户来说，启用此功能可能相当复杂，虽然听起来是个好主意，但在实施之前，它确实存在一些潜在问题，您应该考虑这些问题。如果您想阅读有关在休息时加密您的秘密的步骤，您可以在 Kubernetes 网站上查看[`kubernetes.io/docs/tasks/administer-cluster/encrypt-data/`](https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/)。

保护秘密的另一个选择是使用第三方秘密管理工具，如 HashiCorp 的 Vault 或 CyberArk 的 Conjur。

### 服务账户

Kubernetes 使用服务账户来为工作负载启用访问控制。当您创建一个部署时，可能需要访问其他服务或 Kubernetes 对象。由于 Kubernetes 是一个安全系统，应用程序尝试访问的每个对象或服务都将评估基于角色的访问控制（RBAC）规则以接受或拒绝请求。

使用清单创建服务账户是一个简单的过程，只需要在清单中添加几行代码。以下代码片段显示了用于为 Grafana 部署创建服务账户的服务账户清单：

apiVersion：v1

KinD：ServiceAccount

元数据：

名称：grafana

namespace：监控

您将服务账户与角色绑定和角色结合在一起，以允许访问所需的服务或对象。

### 服务

为了使在 Pod(s)中运行的应用程序对网络可用，您需要创建一个服务。服务对象存储有关如何公开应用程序的信息，包括运行应用程序的 Pods 以及到达它们的网络端口。

每个服务在创建时都分配了一个网络类型，其中包括以下内容：

+   ClusterIP：一种只能在集群内部访问的网络类型。这种类型仍然可以用于使用入口控制器的外部请求，这将在后面的章节中讨论。

+   NodePort：一种网络类型，将服务公开到端口 30000-32767 之间的随机端口。通过定位集群中的任何工作节点，可以访问此端口。创建后，集群中的每个节点都将接收端口信息，并且传入请求将通过 kube-proxy 路由。

+   **LoadBalancer**：这种类型需要一个附加组件才能在集群内部使用。如果您在公共云提供商上运行 Kubernetes，这种类型将创建一个外部负载均衡器，为您的服务分配一个 IP 地址。大多数本地安装的 Kubernetes 不包括对**LoadBalancer**类型的支持，但一些提供商，如谷歌的 Anthos 确实支持它。在后面的章节中，我们将解释如何向 Kubernetes 集群添加一个名为**MetalLB**的开源项目，以提供对**LoadBalancer**类型的支持。

+   **ExternalName**：这种类型与其他三种不同。与其他三种选项不同，这种类型不会为服务分配 IP 地址。相反，它用于将内部 Kubernetes**域名系统**（**DNS**）名称映射到外部服务。

例如，我们部署了一个在端口**80**上运行 Nginx 的 Pod。我们希望创建一个服务，使得该 Pod 可以在集群内从端口**80**接收传入请求。以下代码显示了这个过程：

api 版本：v1

KinD：服务

元数据：

标签：

应用：nginx-web-frontend

名称：nginx-web

规范：

端口：

- 名称：http

端口：80

目标端口：80

选择器：

应用：nginx-web

在我们的清单中，我们创建了一个标签，其值为**app**，并分配了一个值**nginx-web-frontend**。我们将服务本身称为**nginx-web**，并将服务暴露在端口**80**上，目标是**80**端口的 Pod。清单的最后两行用于分配服务将转发到的 Pod，也称为端点。在此清单中，任何在命名空间中具有标签**app**值为**nginx-web**的 Pod 都将被添加为服务的端点。

### 自定义资源定义

**自定义资源定义**（**CRD**）允许任何人通过将应用程序集成到集群中作为标准对象来扩展 Kubernetes。创建 CRD 后，您可以使用 API 端点引用它，并且可以使用标准**kubectl**命令与之交互。

### 守护进程集

**DaemonSet**允许您在集群中的每个节点或节点子集上部署一个 Pod。**DaemonSet**的常见用途是部署日志转发 Pod，如 FluentD 到集群中的每个节点。部署后，**DaemonSet**将在所有现有节点上创建一个 FluentD Pod。由于**DaemonSet**部署到所有节点，一旦将节点添加到集群中，就会启动一个 FluentD Pod。

### 部署

我们之前提到过，您永远不应该直接部署 Pod，并且我们还介绍了 ReplicationContoller 对象作为创建 Pod 的替代方法。虽然这两种方法都会创建您的 Pod，但每种方法都有以下限制：直接创建的 Pod 无法扩展，并且无法使用滚动更新进行升级。

由 ReplicationController 创建的 Pod 可以进行扩展，并可以执行滚动更新。但是，它们不支持回滚，并且无法以声明方式进行升级。

部署为您提供了一些优势，包括以声明方式管理升级的方法以及回滚到先前版本的能力。创建部署实际上是由 API 服务器执行的一个三步过程：创建部署，创建一个 ReplicaSet 对象，然后为应用程序创建 Pod(s)。

即使您不打算使用这些功能，也应该默认使用部署，以便在将来利用这些功能。

### ReplicaSets

ReplicaSets 可用于创建一个 Pod 或一组 Pod（副本）。与 ReplicationController 对象类似，ReplicaSet 对象将维护对象中定义的副本计数的一组 Pod。如果 Pod 太少，Kubernetes 将协调差异并创建缺少的 Pod。如果 ReplicaSet 有太多的 Pod，Kubernetes 将删除 Pod，直到数量等于对象中设置的副本计数为止。

一般来说，您应该避免直接创建 ReplicaSets。相反，您应该创建一个部署，它将创建和管理一个 ReplicaSet。

### StatefulSets

在创建 Pod 时，StatefulSets 提供了一些独特的功能。它们提供了其他 Pod 创建方法所没有的功能，包括以下内容：

+   已知的 Pod 名称

+   有序部署和扩展

+   有序更新

+   持久存储创建

了解 StatefulSet 的优势的最佳方法是查看 Kubernetes 网站上的示例清单，如下截图所示：

![图 5.9 - StatefulSet 清单示例](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/k8s-dkr/img/Fig_5.9_B15514.jpg)

图 5.9 - StatefulSet 清单示例

现在，我们可以看一下 StatefulSet 对象创建的对象。

清单指定应该有三个名为**nginx**的 Pod 副本。当我们获取 Pod 列表时，您会看到使用**nginx**名称创建了三个 Pod，另外带有一个破折号和递增的数字。这就是我们在概述中提到的 Pod 将使用已知名称创建的意思，如下面的代码片段所示：

名称 准备状态 状态 重启 年龄

web-0 1/1 运行中 0 4m6s

web-1 1/1 运行中 0 4m2s

web-2 1/1 运行中 0 3m52s

Pod 也是按顺序创建的——**web-0**必须在创建**web-1**之前完全部署，然后最后是**web-2**。

最后，对于这个示例，我们还在清单中使用**VolumeClaimTemplate**为每个 Pod 添加了一个 PVC。如果您查看**kubectl get pvc**命令的输出，您会看到创建了三个 PVC，名称与我们预期的相同（请注意，由于空间原因，我们删除了**VOLUME**列），如下面的代码片段所示：

名称 状态 容量 访问模式 存储类 年龄

www-web-0 已绑定 1Gi RWO nfs 13m

www-web-1 已绑定 1Gi RWO nfs 13m

www-web-2 已绑定 1Gi RWO nfs 12m

在清单的**VolumeClaimTemplate**部分，您会看到我们将名称**www**分配给了 PVC 声明。当您在 StatefulSet 中分配卷时，PVC 名称将结合在声明模板中使用的名称，与 Pod 的名称结合在一起。使用这种命名，您可以看到为什么 Kubernetes 分配了 PVC 名称**www-web-0**、**www-web-1**和**www-web-2**。

### HorizontalPodAutoscalers

在 Kubernetes 集群上运行工作负载的最大优势之一是能够轻松扩展您的 Pod。虽然您可以使用**kubectl**命令或编辑清单的副本计数来进行扩展，但这些都不是自动化的，需要手动干预。

**HorizontalPodAutoscalers**（**HPAs**）提供了根据一组条件扩展应用程序的能力。使用诸如 CPU 和内存使用率或您自己的自定义指标等指标，您可以设置规则，在需要更多 Pod 来维持服务水平时扩展您的 Pod。冷却期后，Kubernetes 将应用程序缩减到策略中定义的最小 Pod 数。

要快速为**nginx**部署创建 HPA，我们可以使用**autoscale**选项执行**kubectl**命令，如下所示：

kubectl autoscale deployment nginx --cpu-percent=50 --min=1 --max=5

您还可以创建一个 Kubernetes 清单来创建您的 HPAs。使用与我们在 CLI 中使用的相同选项，我们的清单将如下所示：

api 版本：autoscaling/v1

KinD：HorizontalPodAutoscaler

元数据：

名称：nginx-deployment

规范：

最大副本数：5

最小副本数：1

scaleTargetRef：

api 版本：apps/v1

KinD：部署

名称：nginx-deployment

targetCPU 利用率百分比：50

这两个选项都将创建一个 HPA，当部署达到 50%的 CPU 利用率时，将使我们的**nginx-deployment nginx**部署扩展到五个副本。一旦部署使用率低于 50％并且达到冷却期（默认为 5 分钟），副本计数将减少到 1。

### Cron 作业

如果您以前使用过 Linux cron 作业，那么您已经知道 Kubernetes **CronJob**对象是什么。如果您没有 Linux 背景，cron 作业用于创建定期任务。另一个例子，如果您是 Windows 用户，它类似于 Windows 定期任务。

创建**CronJob**的示例清单如下所示：

api 版本：batch/v1beta1

KinD：CronJob

元数据：

名称：hello-world

规范：

计划：“*/1 * * * *”

作业模板：

规范：

模板：

规范：

容器：

- 名称：hello-world

图像：busybox

参数：

- /bin/sh

- -c

- 日期；回声你好，世界！

重启策略：失败时

**计划**格式遵循标准**cron**格式。从左到右，每个*****代表以下内容：

+   分钟（0-59）

+   小时（0-23）

+   日期（1-31）

+   月份（1-12）

+   一周的日期（0-6）（星期日= 0，星期六= 6）

Cron 作业接受步骤值，允许您创建可以每分钟、每 2 分钟或每小时执行的计划。

我们的示例清单将创建一个每分钟运行名为**hello-world**的图像的**cronjob**，并在 Pod 日志中输出**Hello World!**。

### 作业

作业允许您执行特定数量的 Pod 或 Pod 的执行。与**cronjob**对象不同，这些 Pod 不是按照固定的时间表运行的，而是它们一旦创建就会执行。作业用于执行可能只需要在初始部署阶段执行的任务。

一个示例用例可能是一个应用程序，可能需要在主应用程序部署之前创建必须存在的 Kubernetes CRD。部署将等待作业执行成功完成。

### 事件

事件对象存储有关 Kubernetes 对象的事件信息。您不会创建事件；相反，您只能检索事件。例如，要检索**kube-system**命名空间的事件，您将执行**kubectl get events -n kube-system**，或者要显示所有命名空间的事件，您将执行**kubectl get events --all-namespaces**。

### 入口

您可能已经注意到我们的 api-server 输出中**Ingress**对象被列两次。随着 Kubernetes 的升级和 API 服务器中对象的更改，这种情况会发生。在 Ingress 的情况下，它最初是扩展 API 的一部分，并在 1.16 版本中移至**networking.k8s.io** API。该项目将在废弃旧的 API 调用之前等待几个版本，因此在我们的示例集群中运行 Kubernetes 1.17 时，使用任何 API 都可以正常工作。在 1.18 版本中，他们计划完全废弃 Ingress 扩展。

### 网络策略

**NetworkPolicy**对象允许您定义网络流量如何在集群中流动。它们允许您使用 Kubernetes 本机构造来定义哪些 Pod 可以与其他 Pod 通信。如果您曾经在**Amazon Web Services**（**AWS**）中使用安全组来锁定两组系统之间的访问权限，那么这是一个类似的概念。例如，以下策略将允许来自任何带有**app.kubernetes.io/name: ingress-nginx**标签的命名空间的 Pod 上的端口**443**的流量（这是**nginx-ingress**命名空间的默认标签）到**myns**命名空间中的 Pod：

api 版本：networking.k8s.io/v1

KinD：网络策略

元数据：

名称：allow-from-ingress

命名空间：myns

规范：

Pod 选择器：{}

策略类型：

- 入口

入口：

- 来自：

- 命名空间选择器：

匹配标签：

app.kubernetes.io/name：ingress-nginx 端口：

- 协议：TCP

端口：443

**NetworkPolicy**对象是另一个可以用来保护集群的对象。它们应该在所有生产集群中使用，但在多租户集群中，它们应该被视为保护集群中每个命名空间的**必备**。

### Pod 安全策略

**Pod 安全策略**（**PSPs**）是集群如何保护节点免受容器影响的方式。它们允许您限制 Pod 在集群中可以执行的操作。一些示例包括拒绝访问 HostIPC 和 HostPath，并以特权模式运行容器。

我们将在*第十章*中详细介绍 PSPs，*创建 Pod 安全策略*。关于 PSPs 要记住的关键点是，如果没有它们，您的容器几乎可以在节点上执行任何操作。

### ClusterRoleBindings

一旦您定义了**ClusterRole**，您可以通过**ClusterRoleBinding**将其绑定到主题。**ClusterRole**可以绑定到用户、组或 ServiceAccount。

我们将在*第八章**，RBAC Policies and Auditing*中探讨**ClusterRoleBinding**的细节。

### 集群角色

**ClusterRole**结合了一组权限，用于与集群的 API 交互。**ClusterRole**将动词或操作与 API 组合在一起，以定义权限。例如，如果您只希望您的**持续集成/持续交付**（**CI/CD**）流水线能够修补您的部署，以便它可以更新您的图像标记，您可以使用这样的**ClusterRole**：

apiVersion：rbac.authorization.k8s.io/v1

KinD：ClusterRole

元数据：

名称：patch-deployment

规则：

- apiGroups：["apps/v1"]

资源：["deployments"]

动词：["get", "list", "patch"]

**ClusterRole**可以适用于集群和命名空间级别的 API。

### RoleBindings

**RoleBinding**对象是您如何将角色或**ClusterRole**与主题和命名空间关联起来的。例如，以下**RoleBinding**对象将允许**aws-codebuild**用户将**patch-openunison** ClusterRole 应用于**openunison**命名空间：

apiVersion：rbac.authorization.k8s.io/v1

KinD：RoleBinding

元数据：

名称：patch-openunison

命名空间：openunison

主题：

- KinD：用户

名称：aws-codebuild

apiGroup：rbac.authorization.k8s.io

roleRef：

KinD：ClusterRole

名称：patch-deployment

apiGroup：rbac.authorization.k8s.io

即使这引用了**ClusterRole**，它只适用于**openunison**命名空间。如果**aws-codebuild**用户尝试在另一个命名空间中修补部署，API 服务器将阻止它。

### 角色

与**ClusterRole**一样，角色将 API 组和操作组合起来，以定义可以分配给主题的一组权限。**ClusterRole**和**Role**之间的区别在于**Role**只能在命名空间级别定义资源，并且仅适用于特定命名空间。

### CsiDrivers

Kubernetes 使用**CsiDriver**对象将节点连接到存储系统。

您可以通过执行**kubectl get csidriver**命令列出集群中所有可用的 CSI 驱动程序。在我们的一个集群中，我们使用 Netapp 的 SolidFire 进行存储，因此我们的集群安装了 Trident CSI 驱动程序，如下所示：

名称 创建于

csi.trident.netapp.io 2019-09-04T19:10:47Z

### CsiNodes

为了避免在节点 API 对象中存储存储信息，**CSINode**对象被添加到 API 服务器中，用于存储 CSI 驱动程序生成的信息。存储的信息包括将 Kubernetes 节点名称映射到 CSI 节点名称、CSI 驱动程序的可用性和卷拓扑。

### StorageClasses

存储类用于定义存储端点。每个存储类都可以分配标签和策略，允许开发人员为其持久数据选择最佳存储位置。您可以为具有所有**非易失性内存表达**（**NVMe**）驱动器的后端系统创建一个存储类，将其命名为**fast**，同时为运行标准驱动器的 Netapp **网络文件系统**（**NFS**）卷分配一个不同的类，使用名称**standard**。

当请求 PVC 时，用户可以分配他们希望使用的**StorageClass**。当 API 服务器接收到请求时，它会找到匹配的名称，并使用**StorageClass**配置来使用 provisioner 在存储系统上创建卷。

在非常高的层面上，**StorageClass**清单不需要太多的信息。以下是一个使用 Kubernetes 孵化器项目中的 provisioner 提供 NFS 自动配置卷的存储类的示例：

apiVersion: storage.k8s.io/v1 KinD: StorageClass

元数据：

名称：nfs

provisioner: nfs

存储类允许您为用户提供多种存储解决方案。您可以为更便宜、更慢的存储创建一个类，同时为高数据需求提供高吞吐量支持的第二类。通过为每个提供不同的类，您允许开发人员为其应用程序选择最佳选择。

# 摘要

在这一章中，你被投入了一个 Kubernetes 训练营，短时间内呈现了大量的技术材料。试着记住，随着你更深入地了解 Kubernetes 世界，这一切都会变得更容易。我们意识到这一章包含了许多对象的信息。许多对象将在后面的章节中使用，并且将会有更详细的解释。

你了解了每个 Kubernetes 组件以及它们如何相互作用来创建一个集群。有了这些知识，你就有了查看集群中的错误并确定哪个组件可能导致错误或问题的必要技能。我们介绍了集群的控制平面，其中**api-server**、**kube-scheduler**、Etcd 和控制管理器运行。控制平面是用户和服务与集群交互的方式；使用**api-server**和**kube-scheduler**将决定将你的 Pod(s)调度到哪个工作节点上。你还了解了运行**kubelet**和**kube-proxy**组件以及容器运行时的 Kubernetes 节点。

我们介绍了**kubectl**实用程序，你将用它与集群进行交互。你还学习了一些你将在日常使用的常见命令，包括**logs**和**describe**。

在下一章中，我们将创建一个开发 Kubernetes 集群，这将成为剩余章节的基础集群。在本书的其余部分，我们将引用本章介绍的许多对象，通过在实际示例中使用它们来解释它们。

# 问题

1.  Kubernetes 控制平面不包括以下哪个组件？

A. **api-server**

B. **kube-scheduler**

C. Etcd

D. Ingress 控制器

1.  哪个组件负责保存集群的所有信息？

A. **api-server**

B. 主控制器

C. **kubelet**

D. Etcd

1.  哪个组件负责选择运行工作负载的节点？

A. **kubelet**

B. **api-server**

C. **kube-scheduler**

D. **Pod-scheduler**

1.  你会在**kubectl**命令中添加哪个选项来查看命令的额外输出？

A. **冗长**

B. **-v**

C. **–verbose**

D. **-log**

1.  哪种服务类型会创建一个随机生成的端口，允许分配端口的任何工作节点上的传入流量访问该服务？

A. **LoadBalancer**

B. **ClusterIP**

C. 没有—这是所有服务的默认设置

D. **NodePort**

1.  如果你需要在 Kubernetes 集群上部署一个需要已知节点名称和控制每个 Pod 启动的应用程序，你会创建哪个对象？

A. **StatefulSet**

B. **Deployment**

C. **ReplicaSet**

D. **ReplicationController**


# 第六章：服务、负载均衡和外部 DNS

当您将应用程序部署到 Kubernetes 集群时，您的 pod 将被分配临时 IP 地址。由于分配的地址可能会随着 pod 的重新启动而更改，您不应该使用 pod IP 地址来定位服务；相反，您应该使用一个服务对象，它将基于标签将服务 IP 地址映射到后端 pod。如果您需要向外部请求提供服务访问，您可以部署一个 Ingress 控制器，它将根据每个 URL 公开您的服务以接受外部流量。对于更高级的工作负载，您可以部署一个负载均衡器，它将为您的服务提供外部 IP 地址，从而允许您将任何基于 IP 的服务暴露给外部请求。

我们将解释如何通过在我们的 KinD 集群上部署它们来实现这些功能。为了帮助我们理解 Ingress 的工作原理，我们将在集群中部署一个 NGINX Ingress 控制器并公开一个 Web 服务器。由于 Ingress 规则是基于传入的 URL 名称的，我们需要能够提供稳定的 DNS 名称。在企业环境中，这将通过使用标准 DNS 来实现。由于我们使用的是没有 DNS 服务器的开发环境，我们将使用 nip.io 的流行服务。

在本章结束时，我们将解释如何使用 Kubernetes 孵化器项目 external-dns 动态注册服务名称，使用 ETCD 集成的 DNS 区域。

在本章中，我们将涵盖以下主题：

+   将工作负载暴露给请求

+   负载均衡器简介

+   第 7 层负载均衡器

+   第 4 层负载均衡器

+   使服务名称在外部可用

# 技术要求

本章具有以下技术要求：

+   一个新的 Ubuntu 18.04 服务器，至少有 4GB 的 RAM。

+   使用*第四章*中的配置部署 KinD 的集群。

您可以在 GitHub 存储库[`github.com/PacktPublishing/Kubernetes-and-Docker-The-Complete-Guide`](https://github.com/PacktPublishing/Kubernetes-and-Docker-The-Complete-Guide)中访问本章的代码。

# 将工作负载暴露给请求

在 Kubernetes 中最被误解的三个对象是服务、Ingress 控制器和负载均衡器。为了暴露您的工作负载，您需要了解每个对象的工作原理以及可用的选项。让我们详细看看这些。

## 了解服务的工作原理

正如我们在介绍中提到的，任何运行工作负载的 pod 在启动时都被分配一个 IP 地址。许多事件会导致部署重新启动一个 pod，当 pod 重新启动时，它可能会收到一个新的 IP 地址。由于分配给 pod 的地址可能会改变，您不应直接针对 pod 的工作负载。

Kubernetes 提供的最强大的功能之一是能够扩展您的部署。当部署被扩展时，Kubernetes 将创建额外的 pod 来处理任何额外的资源需求。每个 pod 都将有一个 IP 地址，正如您可能知道的，大多数应用程序只针对单个 IP 地址或名称。如果您的应用程序从一个 pod 扩展到十个 pod，您将如何利用额外的 pod？

服务使用 Kubernetes 标签来创建服务本身与运行工作负载的 pod 之间的动态映射。在启动时，运行工作负载的 pod 被标记。每个 pod 都具有与部署中定义的相同的标签。例如，如果我们在部署中使用 NGINX web 服务器，我们将创建一个具有以下清单的部署：

api 版本：apps/v1

类型：部署

元数据：

创建时间戳：null

标签：

run: nginx-frontend

名称：nginx-frontend

规范：

副本：3

选择器：

匹配标签：

run: nginx-frontend

策略：{}

模板：

元数据：

标签：

run: nginx-frontend

规范：

容器：

- 镜像：bitnami/nginx

名称：nginx-frontend

此部署将创建三个 NGINX 服务器，每个 pod 将被标记为**run=nginx-frontend**。我们可以通过使用 kubectl 列出 pod 并添加**--show-labels**选项来验证 pod 是否正确标记，**kubectl get pods --show-labels.**

这将列出每个 pod 和任何相关的标签：

**nginx-frontend-6c4dbf86d4-72cbc           1/1     Running            0          19s    pod-template-hash=6c4dbf86d4,run=nginx-frontend**

**nginx-frontend-6c4dbf86d4-8zlwc           1/1     Running            0          19s    pod-template-hash=6c4dbf86d4,run=nginx-frontend**

**nginx-frontend-6c4dbf86d4-xfz6m           1/1     Running            0          19s    pod-template-hash=6c4dbf86d4,run=nginx-frontend**

从上面的输出中可以看到，每个 pod 都有一个标签**run=nginx-frontend**。在为应用程序创建服务时，您将使用此标签，配置服务以使用标签创建端点。

### 创建服务

现在您知道服务将如何使用标签来创建端点，让我们讨论一下 Kubernetes 中我们拥有的服务选项。

本节将介绍每种服务类型，并向您展示如何创建服务对象。每种类型将在一般介绍之后的各自部分中详细介绍。

Kubernetes 服务可以使用四种类型之一创建：

![表 6.1：Kubernetes 服务类型](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/k8s-dkr/img/Table_1.jpg)

表 6.1：Kubernetes 服务类型

要创建一个服务，您需要创建一个包括**类型**、**选择器**、**类型**和将用于连接到服务的任何**端口**的服务对象。对于我们的 NGINX 部署，我们希望在端口 80 和 443 上公开服务。我们使用**run=nginx-frontend**标记了部署，因此在创建清单时，我们将使用该名称作为我们的选择器：

api 版本：v1

类型：服务

元数据：

标签：

运行：nginx-frontend

名称：nginx-frontend

规范：

选择器：

运行：nginx-frontend

端口：

- 名称：http

端口：80

协议：TCP

目标端口：80

- 名称：https

端口：443

协议：TCP

目标端口：443

类型：ClusterIP

如果服务清单中未定义类型，Kubernetes 将分配默认类型**ClusterIP**。

现在已经创建了一个服务，我们可以使用一些**kubectl**命令来验证它是否被正确定义。我们将执行的第一个检查是验证服务对象是否已创建。要检查我们的服务，我们使用**kubectl get services**命令：

名称                   类型          集群 IP      外部 IP      端口                          年龄 nginx-frontend   ClusterIP   10.43.142.96  <none>            80/TCP,443/TCP   3m49s

在验证服务已创建后，我们可以验证端点是否已创建。使用 kubectl，我们可以通过执行**kubectl get ep <service name>**来验证端点：

名称                  端点                                                                                            年龄

nginx-frontend   10.42.129.9:80,10.42.170.91:80,10.42.183.124:80 + 3 more...   7m49s

我们可以看到服务显示了三个端点，但在端点列表中还显示了**+3 more**。由于输出被截断，get 的输出是有限的，无法显示所有端点。由于我们无法看到整个列表，如果我们描述端点，我们可以获得更详细的列表。使用 kubectl，您可以执行**kubectl describe ep <service name>**命令：

名称：nginx-frontend

命名空间：默认

标签: run=nginx-frontend

注释: endpoints.kubernetes.io/last-change-trigger-time: 2020-04-06T14:26:08Z

子集:

地址: 10.42.129.9,10.42.170.91,10.42.183.124

NotReadyAddresses: <none>

端口:

名称 端口 协议

---- ---- --------

http 80 TCP

https 443 TCP

事件: <none>

如果您比较我们的**get**和**describe**命令的输出，可能会发现端点不匹配。**get**命令显示了总共六个端点：它显示了三个 IP 端点，并且因为它被截断了，它还列出了**+3**，总共六个端点。**describe**命令的输出只显示了三个 IP 地址，而不是六个。为什么这两个输出似乎显示了不同的结果？

**get**命令将在地址列表中列出每个端点和端口。由于我们的服务被定义为公开两个端口，每个地址将有两个条目，一个用于每个公开的端口。地址列表将始终包含服务的每个套接字，这可能会多次列出端点地址，每个套接字一次。

**describe**命令以不同的方式处理输出，将地址列在一行上，下面列出所有端口。乍一看，**describe**命令可能看起来缺少三个地址，但由于它将输出分成多个部分，它只会列出地址一次。所有端口都在地址列表下面分开列出；在我们的示例中，它显示端口 80 和 443。

这两个命令显示相同的数据，但以不同的格式呈现。

现在服务已经暴露给集群，您可以使用分配的服务 IP 地址来连接应用程序。虽然这样可以工作，但是如果服务对象被删除并重新创建，地址可能会更改。您应该使用在创建服务时分配给服务的 DNS，而不是针对 IP 地址。在下一节中，我们将解释如何使用内部 DNS 名称来解析服务。

### 使用 DNS 解析服务

在物理机和虚拟服务器的世界中，您可能已经针对 DNS 记录以与服务器通信。如果服务器的 IP 地址更改了，那么假设您启用了动态 DNS，它对应用程序不会产生任何影响。这就是使用名称而不是 IP 地址作为端点的优势。

当您创建一个服务时，将创建一个内部 DNS 记录，其他工作负载可以查询该记录。如果所有 pod 都在同一个命名空间中，那么我们可以使用简单的短名称如**mysql-web**来定位服务；但是，您可能有一些服务将被多个命名空间使用，当工作负载需要与自己命名空间之外的服务通信时，必须使用完整的名称来定位服务。以下是一个示例表格，显示了如何从命名空间中定位服务：

![表 6.2：内部 DNS 示例](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/k8s-dkr/img/Table_2.jpg)

表 6.2：内部 DNS 示例

从前面的表格中可以看出，您可以使用标准命名约定*.<namespace>.svc.<cluster name>*来定位另一个命名空间中的服务。在大多数情况下，当您访问不同命名空间中的服务时，您不需要添加集群名称，因为它应该会自动添加。

为了加强对一般服务概念的理解，让我们深入了解每种类型的细节以及如何使用它们来访问我们的工作负载。

## 理解不同的服务类型

创建服务时，您需要指定服务类型。分配的服务类型将配置服务如何向集群或外部流量暴露。

### ClusterIP 服务

最常用且被误解的服务类型是 ClusterIP。如果您回顾一下我们的表格，您会看到 ClusterIP 类型的描述指出该服务允许从集群内部连接到该服务。ClusterIP 类型不允许任何外部流量进入暴露的服务。

将服务仅暴露给内部集群工作负载的概念可能会让人感到困惑。为什么要暴露一个只能被集群中的工作负载使用的服务呢？

暂时忘记外部流量。我们需要集中精力关注当前的部署以及每个组件如何相互交互来创建我们的应用程序。以 NGINX 示例为例，我们将扩展部署以包括为 Web 服务器提供服务的后端数据库。

我们的应用程序将有两个部署，一个用于 NGINX 服务器，一个用于数据库服务器。 NGINX 部署将创建五个副本，而数据库服务器将由单个副本组成。 NGINX 服务器需要连接到数据库服务器，以获取网页数据。

到目前为止，这是一个简单的应用程序：我们已经创建了部署，为 NGINX 服务器创建了一个名为 web frontend 的服务，以及一个名为**mysql-web**的数据库服务。为了从 Web 服务器配置数据库连接，我们决定使用一个 ConfigMap，该 ConfigMap 将针对数据库服务。我们在 ConfigMap 中使用什么作为数据库的目的地？

您可能会认为，由于我们只使用单个数据库服务器，我们可以简单地使用 IP 地址。虽然这一开始可能有效，但是对 Pod 的任何重启都会更改地址，Web 服务器将无法连接到数据库。即使只针对单个 Pod，也应始终使用服务。由于数据库部署称为 mysql-web，我们的 ConfigMap 应该使用该名称作为数据库服务器。

通过使用服务名称，当 Pod 重新启动时，我们不会遇到问题，因为服务针对的是标签而不是 IP 地址。我们的 Web 服务器将简单地查询 Kubernetes DNS 服务器以获取服务名称，其中将包含具有匹配标签的任何 Pod 的端点。

### NodePort 服务

NodePort 服务将在集群内部和网络外部公开您的服务。乍一看，这可能看起来像是要公开服务的首选服务。它会向所有人公开您的服务，但它是通过使用称为 NodePort 的东西来实现的，对于外部服务访问，这可能变得难以维护。对于用户来说，使用 NodePort 或记住何时需要通过网络访问服务也非常令人困惑。

要创建使用 NodePort 类型的服务，您只需在清单中将类型设置为 NodePort。我们可以使用之前用于从 ClusterIP 示例中公开 NGINX 部署的相同清单，只需将**类型**更改为**NodePort**：

api 版本：v1

种类：服务

元数据：

标签：

运行：nginx-frontend

名称：nginx-frontend

规范：

选择器：

运行：nginx-frontend

端口：

- 名称：http

端口：80

协议：TCP

目标端口：80

- 名称：https

端口：443

协议：TCP

目标端口：443

类型：NodePort

我们可以以与 ClusterIP 服务相同的方式查看端点，使用 kubectl。运行**kubectl get services**将显示新创建的服务：

名称 类型 CLUSTER-IP 外部 IP 端口 年龄

nginx-frontend NodePort 10.43.164.118 <none> 80:31574/TCP,443:32432/TCP 4s

输出显示类型为 NodePort，并且我们已公开了服务 IP 地址和端口。如果您查看端口，您会注意到，与 ClusterIP 服务不同，NodePort 服务显示两个端口而不是一个。第一个端口是内部集群服务可以定位的公开端口，第二个端口号是从集群外部可访问的随机生成的端口。

由于我们为服务公开了 80 端口和 443 端口，我们将分配两个 NodePort。如果有人需要从集群外部定位服务，他们可以定位任何带有提供的端口的工作节点来访问服务：

![图 6.1 - 使用 NodePort 的 NGINX 服务](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/k8s-dkr/img/Fig_6.1_B15514.jpg)

图 6.1 - 使用 NodePort 的 NGINX 服务

每个节点维护 NodePorts 及其分配的服务列表。由于列表与所有节点共享，您可以使用端口定位任何运行中的节点，Kubernetes 将将其路由到运行中的 pod。

为了可视化流量流向，我们创建了一个图形，显示了对我们的 NGINX pod 的 web 请求：

![图 6.2 - NodePort 流量流向概述](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/k8s-dkr/img/Fig_6.2_B15514.jpg)

图 6.2 - NodePort 流量流向概述

在使用 NodePort 公开服务时，有一些问题需要考虑：

+   如果您删除并重新创建服务，则分配的 NodePort 将更改。

+   如果您瞄准的节点处于离线状态或出现问题，您的请求将失败。

+   对于太多服务使用 NodePort 可能会令人困惑。您需要记住每个服务的端口，并记住服务没有与之关联的*外部*名称。这可能会让瞄准集群中的服务的用户感到困惑。

由于这里列出的限制，您应该限制使用 NodePort 服务。

### 负载均衡器服务

许多刚开始使用 Kubernetes 的人会阅读有关服务的信息，并发现 LoadBalancer 类型将为服务分配外部 IP 地址。由于外部 IP 地址可以被网络上的任何计算机直接寻址，这对于服务来说是一个有吸引力的选项，这就是为什么许多人首先尝试使用它的原因。不幸的是，由于许多用户首先使用本地 Kubernetes 集群，他们在尝试创建 LoadBalancer 服务时遇到了麻烦。

LoadBalancer 服务依赖于与 Kubernetes 集成的外部组件，以创建分配给服务的 IP 地址。大多数本地 Kubernetes 安装不包括这种类型的服务。当您尝试在没有支持基础设施的情况下使用 LoadBalancer 服务时，您会发现您的服务在**EXTERNAL-IP**状态列中显示**<pending>**。

我们将在本章后面解释 LoadBalancer 服务以及如何实现它。

### ExternalName 服务

ExternalName 服务是一种具有特定用例的独特服务类型。当您查询使用 ExternalName 类型的服务时，最终端点不是运行在集群中的 pod，而是外部 DNS 名称。

为了使用您可能在 Kubernetes 之外熟悉的示例，这类似于使用**c-name**来别名主机记录。当您在 DNS 中查询**c-name**记录时，它会解析为主机记录，而不是 IP 地址。

在使用此服务类型之前，您需要了解它可能对您的应用程序造成的潜在问题。如果目标端点使用 SSL 证书，您可能会遇到问题。由于您查询的主机名可能与目标服务器证书上的名称不同，您的连接可能无法成功，因为名称不匹配。如果您发现自己处于这种情况，您可能可以使用在证书中添加**主题替代名称**（**SAN**）的证书。向证书添加替代名称允许您将多个名称与证书关联起来。

为了解释为什么您可能希望使用 ExternalName 服务，让我们使用以下示例：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/k8s-dkr/img/Table_3.jpg)

基于要求，使用 ExternalName 服务是完美的解决方案。那么，我们如何实现这些要求呢？（这是一个理论练习；您不需要在您的 KinD 集群上执行任何操作）

1.  第一步是创建一个清单，将为数据库服务器创建 ExternalName 服务：

api 版本：v1

种类：服务

元数据：

名称：sql-db

命名空间：财务

规范：

类型：ExternalName

externalName: sqlserver1.foowidgets.com

1.  创建了服务之后，下一步是配置应用程序以使用我们新服务的名称。由于服务和应用程序在同一个命名空间中，您可以配置应用程序以定位名称**sql-db**。

1.  现在，当应用程序查询**sql-db**时，它将解析为**sqlserver1.foowidgets.com**，最终解析为 IP 地址 192.168.10.200。

这实现了最初的要求，即仅使用 Kubernetes DNS 服务器将应用程序连接到外部数据库服务器。

也许你会想知道为什么我们不直接配置应用程序使用数据库服务器名称。关键在于第二个要求，即在将 SQL 服务器迁移到容器时限制任何重新配置。

由于在将 SQL 服务器迁移到集群后无法重新配置应用程序，因此我们将无法更改应用程序设置中 SQL 服务器的名称。如果我们配置应用程序使用原始名称**sqlserver1.foowidgets.com**，则迁移后应用程序将无法工作。通过使用 ExternalName 服务，我们可以通过将 ExternalHost 服务名称替换为指向 SQL 服务器的标准 Kubernetes 服务来更改内部 DNS 服务名称。

要实现第二个目标，请按照以下步骤进行：

1.  删除**ExternalName**服务。

1.  使用名称**ext-sql-db**创建一个新的服务，该服务使用**app=sql-app**作为选择器。清单看起来像这样：

api 版本：v1

类型：服务

元数据：

标签：

app: sql-db

名称：sql-db

命名空间：财务

端口：

- 端口：1433

协议：TCP

目标端口：1433

名称：sql

选择器：

应用程序：sql-app

类型：ClusterIP

由于我们为新服务使用相同的服务名称，因此无需对应用程序进行任何更改。该应用程序仍将以**sql-db**为目标名称，现在将使用集群中部署的 SQL 服务器。

现在您已经了解了服务，我们可以继续讨论负载均衡器，这将允许您使用标准 URL 名称和端口外部公开服务。

# 负载均衡器简介

在讨论不同类型的负载均衡器之前，重要的是要了解**开放式系统互联**（**OSI**）模型。了解 OSI 模型的不同层将帮助您了解不同解决方案如何处理传入请求。

## 了解 OSI 模型

当您听到有关在 Kubernetes 中暴露应用程序的不同解决方案时，您经常会听到对第 7 层或第 4 层负载均衡的引用。这些指示是指它们在 OSI 模型中的操作位置。每一层提供不同的功能；在第 7 层运行的组件提供的功能与第 4 层的组件不同。

首先，让我们简要概述一下七层，并对每一层进行描述。在本章中，我们对两个突出显示的部分感兴趣，**第 4 层和第 7 层**：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/k8s-dkr/img/Table_4.jpg)

表 6.3 OSI 模型层

您不需要成为 OSI 层的专家，但您应该了解第 4 层和第 7 层负载均衡器提供的功能以及如何在集群中使用每一层。

让我们深入了解第 4 层和第 7 层的细节：

+   **第 4 层**：正如图表中的描述所述，第 4 层负责设备之间的通信流量。在第 4 层运行的设备可以访问 TCP/UPD 信息。基于第 4 层的负载均衡器为您的应用程序提供了为任何 TCP/UDP 端口服务传入请求的能力。

+   **第 7 层**：第 7 层负责为应用程序提供网络服务。当我们说应用程序流量时，我们指的不是诸如 Excel 或 Word 之类的应用程序；而是指支持应用程序的协议，如 HTTP 和 HTTPS。

在下一节中，我们将解释每种负载均衡器类型以及如何在 Kubernetes 集群中使用它们来暴露您的服务。

# 第 7 层负载均衡器

Kubernetes 以 Ingress 控制器的形式提供第 7 层负载均衡器。有许多解决方案可以为您的集群提供 Ingress，包括以下内容：

+   NGINX

+   Envoy

+   Traefik

+   Haproxy

通常，第 7 层负载均衡器在其可执行的功能方面受到限制。在 Kubernetes 世界中，它们被实现为 Ingress 控制器，可以将传入的 HTTP/HTTPS 请求路由到您暴露的服务。我们将在*创建 Ingress 规则*部分详细介绍如何实现 NGINX 作为 Kubernetes Ingress 控制器。

## 名称解析和第 7 层负载均衡器

要处理 Kubernetes 集群中的第 7 层流量，您需要部署一个 Ingress 控制器。Ingress 控制器依赖于传入的名称来将流量路由到正确的服务。在传统的服务器部署模型中，您需要创建一个 DNS 条目并将其映射到一个 IP 地址。

部署在 Kubernetes 集群上的应用程序与此无异-用户将使用 DNS 名称访问应用程序。

通常，您将创建一个新的通配符域，将其定位到 Ingress 控制器，通过外部负载均衡器，如 F5、HAproxy 或 SeeSaw。

假设我们的公司叫 FooWidgets，我们有三个 Kubernetes 集群，由多个 Ingress 控制器端点作为前端的外部负载均衡器。我们的 DNS 服务器将为每个集群添加条目，使用通配符域指向负载均衡器的虚拟 IP 地址：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/k8s-dkr/img/Table_5.jpg)

表 6.4 Ingress 的通配符域名示例

以下图表显示了请求的整个流程：

![图 6.3 - 多名称 Ingress 流量](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/k8s-dkr/img/Fig_6.3_B15514.jpg)

图 6.3 - 多名称 Ingress 流量

图 6.3 中的每个步骤在这里详细说明：

1.  使用浏览器，用户请求 URL [`timesheets.cluster1.foowidgets.com`](https://timesheets.cluster1.foowidgets.com)。

1.  DNS 查询被发送到 DNS 服务器。DNS 服务器查找**cluster1.foowidgets.com**的区域详细信息。DNS 区域中有一个单一条目解析为该域的负载均衡器分配的 VIP。

1.  **cluster1.foowidgets.com**的负载均衡器 VIP 分配了三个后端服务器，指向我们部署了 Ingress 控制器的三个工作节点。

1.  使用其中一个端点，请求被发送到 Ingress 控制器。

1.  Ingress 控制器将请求的 URL 与 Ingress 规则列表进行比较。当找到匹配的请求时，Ingress 控制器将请求转发到分配给 Ingress 规则的服务。

为了帮助加强 Ingress 的工作原理，创建 Ingress 规则并在集群上查看它们的运行情况将会有所帮助。现在，关键要点是 Ingress 使用请求的 URL 将流量定向到正确的 Kubernetes 服务。

## 使用 nip.io 进行名称解析

大多数个人开发集群，例如我们的 KinD 安装，可能没有足够的访问权限来向 DNS 服务器添加记录。为了测试 Ingress 规则，我们需要将唯一主机名定位到由 Ingress 控制器映射到 Kubernetes 服务的 IP 地址的本地主机文件中，而不需要 DNS 服务器。

例如，如果您部署了四个 Web 服务器，您需要将所有四个名称添加到您的本地主机。这里显示了一个示例：

**192.168.100.100 webserver1.test.local**

**192.168.100.100 webserver2.test.local**

**192.168.100.100 webserver3.test.local**

**192.168.100.100 webserver4.test.local**

这也可以表示为单行而不是多行：

**192.168.100.100 webserver1.test.local webserver2.test.local webserver3.test.local webserver4.test.local**

如果您使用多台机器来测试您的部署，您将需要编辑每台机器上的 host 文件。在多台机器上维护多个文件是一场管理噩梦，并将导致问题，使测试变得具有挑战性。

幸运的是，有免费的服务可用，提供了 DNS 服务，我们可以在 KinD 集群中使用，而无需配置复杂的 DNS 基础设施。

Nip.io 是我们将用于 KinD 集群名称解析需求的服务。使用我们之前的 Web 服务器示例，我们将不需要创建任何 DNS 记录。我们仍然需要将不同服务器的流量发送到运行在 192.168.100.100 上的 NGINX 服务器，以便 Ingress 可以将流量路由到适当的服务。Nip.io 使用包含 IP 地址在主机名中的命名格式来将名称解析为 IP。例如，假设我们有四台我们想要测试的 Web 服务器，分别为 webserver1、webserver2、webserver3 和 webserver4，Ingress 控制器运行在 192.168.100.100 上。

正如我们之前提到的，我们不需要创建任何记录来完成这个任务。相反，我们可以使用命名约定让 nip.io 为我们解析名称。每台 Web 服务器都将使用以下命名标准的名称：

**<desired name>.<INGRESS IP>.nip.io**

所有四台 Web 服务器的名称列在下表中：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/k8s-dkr/img/Table_6.jpg)

表 6.5–Nip.io 示例域名

当您使用任何上述名称时，nip.io 将把它们解析为 192.168.100.100。您可以在以下截图中看到每个名称的 ping 示例：

![图 6.4–使用 nip.io 进行名称解析的示例](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/k8s-dkr/img/Fig_6.4_B15514.jpg)

图 6.4–使用 nip.io 进行名称解析的示例

这看起来好像没有什么好处，因为您在名称中提供了 IP 地址。如果您知道 IP 地址，为什么还需要使用 nip.io 呢？

请记住，Ingress 规则需要一个唯一的名称来将流量路由到正确的服务。虽然对于您来说可能不需要知道服务器的 IP 地址，但是对于 Ingress 规则来说，名称是必需的。每个名称都是唯一的，使用完整名称的第一部分——在我们的示例中，即**webserver1**、**webserver2**、**webserver3**和**webserver4**。

通过提供这项服务，nip.io 允许您在开发集群中使用任何名称的 Ingress 规则，而无需拥有 DNS 服务器。

现在您知道如何使用 nip.io 来解析集群的名称，让我们解释如何在 Ingress 规则中使用 nip.io 名称。

## 创建 Ingress 规则

记住，Ingress 规则使用名称来将传入的请求路由到正确的服务。以下是传入请求的图形表示，显示了 Ingress 如何路由流量：

![图 6.5 – Ingress 流量流向](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/k8s-dkr/img/Fig_6.5_B15514.jpg)

图 6.5 – Ingress 流量流向

图 6.5 显示了 Kubernetes 如何处理传入的 Ingress 请求的高级概述。为了更深入地解释每个步骤，让我们更详细地介绍一下五个步骤。使用图 6.5 中提供的图形，我们将详细解释每个编号步骤，以展示 Ingress 如何处理请求：

1.  用户在其浏览器中请求名为 webserver1.192.168.200.20.nio.io 的 URL。DNS 请求被发送到本地 DNS 服务器，最终发送到 nip.io DNS 服务器。

1.  nip.io 服务器将域名解析为 IP 地址 192.168.200.20，并返回给客户端。

1.  客户端将请求发送到运行在 192.168.200.20 上的 Ingress 控制器。请求包含完整的 URL 名称**webserver1.192.168.200.20.nio.io**。

1.  Ingress 控制器在配置的规则中查找请求的 URL 名称，并将 URL 名称与服务匹配。

1.  服务端点将用于将流量路由到分配的 pod。

1.  请求被路由到运行 web 服务器的端点 pod。

使用前面的示例流量流向，让我们来看看需要创建的 Kubernetes 对象：

1.  首先，我们需要在一个命名空间中运行一个简单的 web 服务器。我们将在默认命名空间中简单部署一个基本的 NGINX web 服务器。我们可以使用以下**kubectl run**命令快速创建一个部署，而不是手动创建清单：

**kubectl run nginx-web --image bitnami/nginx**

1.  使用**run**选项是一个快捷方式，它将在默认命名空间中创建一个名为**nginx-web**的部署。您可能会注意到输出会给出一个警告，即 run 正在被弃用。这只是一个警告；它仍然会创建我们的部署，尽管在将来的 Kubernetes 版本中使用**run**创建部署可能不起作用。

1.  接下来，我们需要为部署创建一个服务。同样，我们将使用 kubectl 命令**kubectl expose**创建一个服务。Bitnami NGINX 镜像在端口 8080 上运行，因此我们将使用相同的端口来暴露服务：

**kubectl expose deployment nginx-web --port 8080 --target-port 8080**

这将为我们的部署创建一个名为 nginx-web 的新服务，名为 nginx-web。

1.  现在我们已经创建了部署和服务，最后一步是创建 Ingress 规则。要创建 Ingress 规则，您需要使用对象类型**Ingress**创建一个清单。以下是一个假设 Ingress 控制器正在运行在 192.168.200.20 上的示例 Ingress 规则。如果您在您的主机上创建此规则，您应该使用**您的 Docker 主机的 IP 地址**。

创建一个名为**nginx-ingress.yaml**的文件，其中包含以下内容：

apiVersion: networking.k8s.io/v1beta1

kind: Ingress

metadata:

name: nginx-web-ingress

spec:

规则：

- host: webserver1.192.168.200.20.nip.io

http:

paths:

- path: /

后端：

serviceName: nginx-web

servicePort: 8080

1.  使用**kubectl apply**创建 Ingress 规则：

**kubectl apply -f nginx-ingress.yaml**

1.  您可以通过浏览到 Ingress URL **http:// webserver1.192.168.200.20.nip.io** 来从内部网络上的任何客户端测试部署。

1.  如果一切创建成功，您应该看到 NGINX 欢迎页面：

![图 6.6 - 使用 nip.io 创建 Ingress 的 NGINX web 服务器](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/k8s-dkr/img/Fig_6.6_B15514.jpg)

图 6.6 - 使用 nip.io 创建 Ingress 的 NGINX web 服务器

使用本节中的信息，您可以使用不同的主机名为多个容器创建 Ingress 规则。当然，您并不局限于使用像 nip.io 这样的服务来解析名称；您可以使用您在环境中可用的任何名称解析方法。在生产集群中，您将拥有企业 DNS 基础设施，但在实验环境中，比如我们的 KinD 集群，nip.io 是测试需要适当命名约定的场景的完美工具。

我们将在整本书中使用 nip.io 命名标准，因此在继续下一章之前了解命名约定非常重要。

许多标准工作负载使用第 7 层负载均衡器，例如 NGINX Ingress，比如 Web 服务器。将有一些部署需要更复杂的负载均衡器，这种负载均衡器在 OIS 模型的较低层运行。随着我们向模型下移，我们获得了更低级别的功能。在下一节中，我们将讨论第 4 层负载均衡器。

注意

如果您在集群上部署了 NGINX 示例，应删除服务和 Ingress 规则：

• 要删除 Ingress 规则，请执行以下操作：**kubectl delete ingress nginx-web-ingress**

• 要删除服务，请执行以下操作：**kubectl delete service nginx-web**

您可以让 NGINX 部署在下一节继续运行。

# 第 4 层负载均衡器

OSI 模型的第 4 层负责 TCP 和 UDP 等协议。在第 4 层运行的负载均衡器根据唯一的 IP 地址和端口接受传入的流量。负载均衡器接受传入请求，并根据一组规则将流量发送到目标 IP 地址和端口。

在这个过程中有一些较低级别的网络操作超出了本书的范围。HAproxy 在他们的网站上有术语和示例配置的很好总结，网址为[`www.haproxy.com/fr/blog/loadbalancing-faq/`](https://www.haproxy.com/fr/blog/loadbalancing-faq/)。

## 第 4 层负载均衡器选项

如果您想为 Kubernetes 集群配置第 4 层负载均衡器，可以选择多种选项。其中一些选项包括以下内容：

+   HAproxy

+   NGINX Pro

+   秋千

+   F5 网络

+   MetalLB

+   等等...

每个选项都提供第 4 层负载均衡，但出于本书的目的，我们认为 MetalLB 是最好的选择。

## 使用 MetalLB 作为第 4 层负载均衡器

重要提示

请记住，在*第四章* *使用 KinD 部署 Kubernetes*中，我们有一个图表显示了工作站和 KinD 节点之间的流量流向。因为 KinD 在嵌套的 Docker 容器中运行，所以在涉及网络连接时，第 4 层负载均衡器会有一定的限制。如果没有在 Docker 主机上进行额外的网络配置，您将无法将 LoadBalancer 类型的服务定位到 Docker 主机之外。

如果您将 MetalLB 部署到运行在主机上的标准 Kubernetes 集群中，您将不受限于访问主机外的服务。

MetalLB 是一个免费、易于配置的第 4 层负载均衡器。它包括强大的配置选项，使其能够在开发实验室或企业集群中运行。由于它如此多才多艺，它已成为需要第 4 层负载均衡的集群的非常受欢迎的选择。

在本节中，我们将专注于在第 2 层模式下安装 MetalLB。这是一个简单的安装，适用于开发或小型 Kubernetes 集群。MetalLB 还提供了使用 BGP 模式部署的选项，该选项允许您建立对等伙伴以交换网络路由。如果您想阅读 MetalLB 的 BGP 模式，请访问 MetalLB 网站 [`metallb.universe.tf/concepts/bgp/`](https://metallb.universe.tf/concepts/bgp/)。

### 安装 MetalLB

要在您的 KinD 集群上部署 MetalLB，请使用 MetalLB 的 GitHub 存储库中的清单。要安装 MetalLB，请按照以下步骤进行：

1.  以下将创建一个名为**metallb-system**的新命名空间，并带有**app: metallb**的标签：

**kubectl apply -f https://raw.githubusercontent.com/metallb/metallb/v0.9.3/manifests/namespace.yaml**

1.  这将在您的集群中部署 MetalLB。它将创建所有必需的 Kubernetes 对象，包括**PodSecurityPolicies**，**ClusterRoles**，**Bindings**，**DaemonSet**和一个**deployment**：

**kubectl apply -f https://raw.githubusercontent.com/metallb/metallb/v0.9.3/manifests/metallb.yaml**

1.  最后一个命令将在**metalb-system**命名空间中创建一个具有随机生成值的秘密。MetalLB 使用此秘密来加密发言者之间的通信：

**kubectl create secret generic -n metallb-system memberlist --from-literal=secretkey="$(openssl rand -base64 128)"**

现在 MetalLB 已部署到集群中，您需要提供一个配置文件来完成设置。

### 理解 MetalLB 的配置文件

MetalLB 使用包含配置的 ConfigMap 进行配置。由于我们将在第 2 层模式下使用 MetalLB，所需的配置文件相当简单，只需要一个信息：您想为服务创建的 IP 范围。

为了保持配置简单，我们将在 KinD 正在运行的 Docker 子网中使用一个小范围。如果您在标准 Kubernetes 集群上运行 MetalLB，您可以分配任何在您的网络中可路由的范围，但我们在 KinD 集群中受到限制。

要获取 Docker 正在使用的子网，我们可以检查我们正在使用的默认桥接网络：

**docker 网络检查桥接**

在输出中，您将看到分配的子网，类似于以下内容：

**"子网"："172.17.0.0/16"**

这是一个完整的 B 类地址范围。我们知道我们不会使用所有 IP 地址来运行容器，因此我们将在 MetalLB 配置中使用子网中的一个小范围。

让我们创建一个名为**metallb-config.yaml**的新文件，并将以下内容添加到文件中：

apiVersion：v1

种类：ConfigMap

元数据：

命名空间：metallb-system

名称：config

数据：

配置：|

地址池：

- 名称：默认

协议：layer2

地址：

- 172.17.200.100-172.17.200.125

该清单将在**metallb-system**命名空间中创建一个名为**config**的 ConfigMap。配置文件将设置 MetalLB 的模式为第 2 层，使用名为**default**的 IP 池，为负载均衡器服务使用 172.16.200-100 到 172.16.200.125 的范围。

您可以根据配置名称分配不同的地址。我们将在解释如何创建负载均衡器服务时展示这一点。

最后，使用 kubectl 部署清单：

**kubectl apply -f metallb-config.yaml**

要了解 MetalLB 的工作原理，您需要了解安装的组件以及它们如何相互作用来为服务分配 IP 地址。

### MetalLB 组件

部署中的第二个清单是安装 MetalLB 组件到集群的清单。它部署了一个包含 speaker 镜像的 DaemonSet 和一个包含 controller 镜像的 DaemonSet。这些组件相互通信，以维护服务列表和分配的 IP 地址：

#### 发言者

发言者组件是 MetaLB 用来在节点上宣布负载均衡器服务的组件。它部署为 DaemonSet，因为部署可以在任何工作节点上，因此每个工作节点都需要宣布正在运行的工作负载。当使用负载均衡器类型创建服务时，发言者将宣布该服务。

如果我们从节点查看发言者日志，我们可以看到以下公告：

**{"caller":"main.go:176","event":"startUpdate","msg":"start of service update","service":"my-grafana-operator/grafana-operator-metrics","ts":"2020-04-21T21:10:07.437231123Z"}**

**{"caller":"main.go:189","event":"endUpdate","msg":"end of service update","service":"my-grafana-operator/grafana-operator-metrics","ts":"2020-04-21T21:10:07.437516541Z"}**

**{"caller":"main.go:176","event":"startUpdate","msg":"start of service update","service":"my-grafana-operator/grafana-operator-metrics","ts":"2020-04-21T21:10:07.464140524Z"}**

**{"caller":"main.go:246","event":"serviceAnnounced","ip":"10.2.1.72","msg":"service has IP, announcing","pool":"default","protocol":"layer2","service":"my-grafana-operator/grafana-operator-metrics","ts":"2020-04-21T21:10:07.464311087Z"}**

**{"caller":"main.go:249","event":"endUpdate","msg":"end of service update","service":"my-grafana-operator/grafana-operator-metrics","ts":"2020-04-21T21:10:07.464470317Z"}**

前面的公告是为 Grafana。在公告之后，您可以看到它被分配了 IP 地址 10.2.1.72。

#### 控制器

控制器将从每个工作节点的扬声器接收公告。使用先前显示的相同服务公告，控制器日志显示了公告和控制器为服务分配的 IP 地址：

**{"caller":"main.go:49","event":"startUpdate","msg":"start of service update","service":"my-grafana-operator/grafana-operator-metrics","ts":"2020-04-21T21:10:07.437701161Z"}**

**{"caller":"service.go:98","event":"ipAllocated","ip":"10.2.1.72","msg":"IP address assigned by controller","service":"my-grafana-operator/grafana-operator-metrics","ts":"2020-04-21T21:10:07.438079774Z"}**

**{"caller":"main.go:96","event":"serviceUpdated","msg":"updated service object","service":"my-grafana-operator/grafana-operator-metrics","ts":"2020-04-21T21:10:07.467998702Z"}**

在日志的第二行中，您可以看到控制器分配了 IP 地址 10.2.1.72。

## 创建一个 LoadBalancer 服务

现在您已经安装了 MetalLB 并了解了组件如何创建服务，让我们在我们的 KinD 集群上创建我们的第一个 LoadBalancer 服务。

在第 7 层负载均衡器部分，我们创建了一个运行 NGINX 的部署，并通过创建服务和 Ingress 规则来公开它。在本节的末尾，我们删除了服务和 Ingress 规则，但保留了 NGINX 部署。如果您按照 Ingress 部分的步骤并且尚未删除服务和 Ingress 规则，请在创建 LoadBalancer 服务之前这样做。如果您根本没有创建部署，则需要一个 NGINX 部署来完成本节：

1.  您可以通过执行以下命令快速创建一个 NGINX 部署：

kubectl run nginx-web --image bitnami/nginx

1.  要创建一个将使用 LoadBalancer 类型的新服务，您可以创建一个新的清单，或者只使用 kubectl 公开部署。

要创建一个清单，请创建一个名为**nginx-lb.yaml**的新文件，并添加以下内容：

apiVersion: v1

kind: Service

metadata:

名称：nginx-lb

spec:

端口：

- 端口：8080

targetPort: 8080

selector:

run: nginx-web

type: LoadBalancer

1.  使用 kubectl 将文件应用到集群：

**kubectl apply -f nginx-lb.yaml**

1.  要验证服务是否正确创建，请使用**kubectl get services**列出服务：![图 6.7 - Kubectl 服务输出](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/k8s-dkr/img/Fig_6.7_B15514.jpg)

图 6.7 - Kubectl 服务输出

您将看到使用 LoadBalancer 类型创建了一个新服务，并且 MetalLB 从我们之前创建的配置池中分配了一个 IP 地址。

快速查看控制器日志将验证 MetalLB 控制器分配了 IP 地址给服务：

**{"caller":"service.go:114","event":"ipAllocated","ip":"172.16.200.100","msg":"IP address assigned by controller","service":"default/nginx-lb","ts":"2020-04-25T23:54:03.668948668Z"}**

1.  现在您可以在 Docker 主机上使用**curl**来测试服务。使用分配给服务的 IP 地址和端口 8080，输入以下命令：

**curl 172.17.200.100:8080**

您将收到以下输出：

![图 6.8 - Curl 输出到运行 NGINX 的 LoadBalancer 服务](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/k8s-dkr/img/Fig_6.8_B15514.jpg)

图 6.8 - Curl 输出到运行 NGINX 的 LoadBalancer 服务

将 MetalLB 添加到集群中，允许您暴露其他情况下无法使用第 7 层负载均衡器暴露的应用程序。在集群中添加第 7 层和第 4 层服务，允许您暴露几乎任何类型的应用程序，包括数据库。如果您想要为服务提供不同的 IP 池怎么办？在下一节中，我们将解释如何创建多个 IP 池，并使用注释将其分配给服务，从而允许您为服务分配 IP 范围。

## 向 MetalLB 添加多个 IP 池

可能有一些情况下，您需要为集群上的特定工作负载提供不同的子网。一个情况可能是，当您为您的服务在网络上创建一个范围时，您低估了会创建多少服务，导致 IP 地址用尽。

根据您使用的原始范围，您可能只需增加配置中的范围。如果无法扩展现有范围，则需要在创建任何新的 LoadBalancer 服务之前创建一个新范围。您还可以向默认池添加其他 IP 范围，但在本例中，我们将创建一个新池。

我们可以编辑配置文件，并将新的范围信息添加到文件中。使用原始的 YAML 文件**metallb-config.yaml**，我们需要在以下代码中添加粗体文本：

apiVersion：v1

种类：ConfigMap

元数据：

命名空间：metallb-system

名称：配置

数据：

配置：|

地址池：

- 名称：默认

协议：layer2

地址：

- 172.17.200.100-172.17.200.125

- 名称：subnet-201

协议：layer2

地址：

- 172.17.200.100-172.17.200.125

应用使用**kubectl**更新 ConfigMap：

**kubectl apply -f metallb-config.yaml**

更新后的 ConfigMap 将创建一个名为 subnet-201 的新池。MetalLB 现在有两个池，可以用来为服务分配 IP 地址：默认和 subnet-201。

如果用户创建了一个 LoadBalancer 服务，但没有指定池名称，Kubernetes 将尝试使用默认池。如果请求的池中没有地址，服务将处于挂起状态，直到有地址可用。

要从第二个池创建一个新服务，您需要向服务请求添加注释。使用我们的 NGINX 部署，我们将创建一个名为**nginx-web2**的第二个服务，该服务将从 subnet-201 池请求一个 IP 地址：

1.  创建一个名为**nginx-lb2.yaml**的新文件，其中包含以下内容：

apiVersion：v1

种类：服务

元数据：

名称：nginx-lb2

注释：

metallb.universe.tf/address-pool: subnet-201

规范：

端口：

- 端口：8080

目标端口：8080

选择器：

运行：nginx-web

类型：负载均衡器

1.  要创建新服务，请使用 kubectl 部署清单：

**kubectl apply -f nginx-lb2.yaml**

1.  要验证服务是否使用了子网 201 地址池中的 IP 地址创建，请列出所有服务：

**kubectl get services**

您将收到以下输出：

![图 6.9 - 使用 LoadBalancer 的示例服务](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/k8s-dkr/img/Fig_6.9_B15514.jpg)

图 6.9 - 使用 LoadBalancer 的示例服务

列表中的最后一个服务是我们新创建的**nginx-lb2**服务。我们可以确认它已被分配了一个外部 IP 地址 172.17.20.100，这是来自子网 201 地址池的。

1.  最后，我们可以通过在 Docker 主机上使用**curl**命令，连接到分配的 IP 地址的 8080 端口来测试服务：

![图 6.10 - 在第二个 IP 池上使用 Curl NGINX 的负载均衡器](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/k8s-dkr/img/Fig_6.10_B15514.jpg)

图 6.10 - 在第二个 IP 池上使用 Curl NGINX 的负载均衡器

拥有提供不同地址池的能力，允许您为服务分配已知的 IP 地址块。您可以决定地址池 1 用于 Web 服务，地址池 2 用于数据库，地址池 3 用于文件传输，依此类推。一些组织这样做是为了根据 IP 分配来识别流量，使跟踪通信更容易。

向集群添加第 4 层负载均衡器允许您迁移可能无法处理简单第 7 层流量的应用程序。

随着更多应用程序迁移到容器或进行重构，您将遇到许多需要单个服务的多个协议的应用程序。如果您尝试创建同时具有 TCP 和 UDP 端口映射的服务，您将收到一个错误，即服务对象不支持多个协议。这可能不会影响许多应用程序，但为什么您应该被限制为单个协议的服务呢？

### 使用多个协议

到目前为止，我们的所有示例都使用 TCP 作为协议。当然，MetalLB 也支持使用 UDP 作为服务协议，但如果您有一个需要同时使用两种协议的服务呢？

## 多协议问题

并非所有服务类型都支持为单个服务分配多个协议。以下表格显示了三种服务类型及其对多个协议的支持：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/k8s-dkr/img/Table_7.jpg)

表 6.6 - 服务类型协议支持

如果你尝试创建一个同时使用两种协议的服务，你将会收到一个错误信息。我们已经在下面的错误信息中突出显示了这个错误：

服务"kube-dns-lb"是无效的：spec.ports: 无效的值: []core.ServicePort{core.ServicePort{Name:"dns", Protocol:"UDP", Port:53, TargetPort:intstr.IntOrString{Type:0, IntVal:53, StrVal:""}, NodePort:0}, core.ServicePort{Name:"dns-tcp", Protocol:"TCP", Port:53, TargetPort:intstr.IntOrString{Type:0, IntVal:53, StrVal:""}, NodePort:0}}: **无法创建混合协议的外部负载均衡器**

我们试图创建的服务将使用 LoadBalancer 服务将我们的 CoreDNS 服务暴露给外部 IP。我们需要在端口 50 上同时为 TCP 和 UDP 暴露服务。

MetalLB 包括对绑定到单个 IP 地址的多个协议的支持。这种配置需要创建两个不同的服务，而不是一个单一的服务，这一开始可能看起来有点奇怪。正如我们之前所展示的，API 服务器不允许你创建一个具有多个协议的服务对象。绕过这个限制的唯一方法是创建两个不同的服务：一个分配了 TCP 端口，另一个分配了 UDP 端口。

使用我们的 CoreDNS 例子，我们将逐步介绍创建一个需要多个协议的应用程序的步骤。

## 使用 MetalLB 的多个协议

为了支持一个需要 TCP 和 UDP 的应用程序，你需要创建两个单独的服务。如果你一直在关注服务的创建方式，你可能已经注意到每个服务都会得到一个 IP 地址。逻辑上讲，这意味着当我们为我们的应用程序创建两个服务时，我们将得到两个不同的 IP 地址。

在我们的例子中，我们想要将 CoreDNS 暴露为一个 LoadBalancer 服务，这需要 TCP 和 UDP 协议。如果我们创建了两个标准服务，一个定义了每种协议，我们将会得到两个不同的 IP 地址。你会如何配置一个需要两个不同 IP 地址的 DNS 服务器的连接？

简单的答案是，**你不能**。

但是我们刚告诉你，MetalLB 支持这种类型的配置。跟着我们走——我们首先要解释 MetalLB 将为我们解决的问题。

当我们之前创建了从 subnet-201 IP 池中提取的 NGINX 服务时，是通过向负载均衡器清单添加注释来实现的。 MetalLB 通过为**shared-IPs**添加注释来添加对多个协议的支持。

## 使用共享 IP

现在您了解了 Kubernetes 中多协议支持的限制，让我们使用 MetalLB 来将我们的 CoreDNS 服务暴露给外部请求，同时使用 TCP 和 UDP。

正如我们之前提到的，Kubernetes 不允许您创建具有两种协议的单个服务。要使单个负载均衡 IP 使用两种协议，您需要为两种协议创建一个服务，一个用于 TCP，另一个用于 UDP。每个服务都需要一个 MetalLB 将使用它来为两个服务分配相同 IP 的注释。

对于每个服务，您需要为**metallb.universe.tf/allow-shared-ip**注释设置相同的值。我们将介绍一个完整的示例来公开 CoreDNS 以解释整个过程。

重要说明

大多数 Kubernetes 发行版使用 CoreDNS 作为默认的 DNS 提供程序，但其中一些仍然使用了 kube-dns 作为默认 DNS 提供程序时的服务名称。 KinD 是其中一个可能会让你感到困惑的发行版，因为服务名称是 kube-dns，但请放心，部署正在使用 CoreDNS。

所以，让我们开始：

1.  首先，查看**kube-system**命名空间中的服务：![图 6.11- kube-system 的默认服务列表](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/k8s-dkr/img/Fig_6.11_B15514.jpg)

图 6.11- kube-system 的默认服务列表

我们唯一拥有的服务是默认的**kube-dns**服务，使用 ClusterIP 类型，这意味着它只能在集群内部访问。

您可能已经注意到该服务具有多协议支持，分配了 UDP 和 TCP 端口。请记住，与 LoadBalancer 服务不同，ClusterIP 服务**可以**分配多个协议。

1.  为了为我们的 CoreDNS 服务器添加 LoadBalancer 支持的第一步是创建两个清单，每个协议一个。

我们将首先创建 TCP 服务。创建一个名为**coredns-tcp.yaml**的文件，并添加以下示例清单中的内容。请注意，CoreDNS 的内部服务使用**k8s-app：kube-dns**选择器。由于我们正在公开相同的服务，这就是我们在清单中将使用的选择器：

apiVersion：v1

种类：服务

元数据：

名称：coredns-tcp

命名空间：kube-system

注释：

metallb.universe.tf/allow-shared-ip: "coredns-ext"

规范：

选择器：

k8s-app：kube-dns

端口：

- 名称：dns-tcp

端口：53

协议：TCP

targetPort: 53

类型：负载均衡器

这个文件现在应该很熟悉了，唯一的例外是注释中添加了**metallb.universe.tf/allow-shared-ip**值。当我们为 UDP 服务创建下一个清单时，这个值的用途将变得清晰。

1.  创建一个名为**coredns-udp.yaml**的文件，并添加以下示例清单中的内容。

api 版本：v1

种类：服务

元数据：

名称：coredns-udp

命名空间：kube-system

注释：

metallb.universe.tf/allow-shared-ip: "coredns-ext"

规范：

选择器：

k8s-app：kube-dns

端口：

- 名称：dns-tcp

端口：53

协议：UDP

targetPort: 53

类型：负载均衡器

请注意，我们从 TCP 服务清单中使用了相同的注释值**metallb.universe.tf/allow-shared-ip: "coredns-ext"**。这是 MetalLB 将使用的值，即使请求了两个单独的服务，也会创建一个单一的 IP 地址。

1.  最后，我们可以使用**kubectl apply**将这两个服务部署到集群中：

**kubectl apply -f coredns-tcp.yaml kubectl apply -f coredns-udp.yaml**

1.  一旦部署完成，获取**kube-system**命名空间中的服务，以验证我们的服务是否已部署：

![图 6.12 - 使用 MetalLB 分配多个协议](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/k8s-dkr/img/Fig_6.12_B15514.jpg)

图 6.12 - 使用 MetalLB 分配多个协议

您应该看到已创建了两个新服务：**coredns-tcp**和**coredns-udp**服务。在**EXTERNAL-IP**列下，您可以看到这两个服务都被分配了相同的 IP 地址，这允许服务在同一个 IP 地址上接受两种协议。

将 MetalLB 添加到集群中，使用户能够部署任何可以容器化的应用程序。它使用动态分配 IP 地址的 IP 池，以便立即为外部请求提供服务。

一个问题是 MetalLB 不为服务 IP 提供名称解析。用户更喜欢以易记的名称为目标，而不是在访问服务时使用随机 IP 地址。Kubernetes 不提供为服务创建外部可访问名称的能力，但它有一个孵化器项目来启用此功能。

在下一节中，我们将学习如何使用 CoreDNS 使用一个名为 external-dns 的孵化器项目在 DNS 中创建服务名称条目。

# 使服务名称在外部可用

您可能一直在想为什么我们在测试我们创建的 NGINX 服务时使用 IP 地址，而在 Ingress 测试中使用域名。

虽然 Kubernetes 负载均衡器为服务提供了标准的 IP 地址，但它并不为用户创建外部 DNS 名称以连接到服务。使用 IP 地址连接到集群上运行的应用程序并不是非常有效，手动为 MetalLB 分配的每个 IP 注册 DNS 名称将是一种不可能维护的方法。那么，如何为我们的负载均衡器服务添加名称解析提供更类似云的体验呢？

类似于维护 KinD 的团队，有一个名为**external-dns**的 Kubernetes SIG 正在开发这个功能。主项目页面位于 SIG 的 Github 上[`github.com/kubernetes-sigs/external-dns`](https://github.com/kubernetes-sigs/external-dns)。

在撰写本文时，**external-dns**项目支持一长串兼容的 DNS 服务器，包括以下内容：

+   谷歌的云 DNS

+   亚马逊的 Route 53

+   AzureDNS

+   Cloudflare

+   CoreDNS

+   RFC2136

+   还有更多...

正如您所知，我们的 Kubernetes 集群正在运行 CoreDNS 以提供集群 DNS 名称解析。许多人不知道 CoreDNS 不仅限于提供内部集群 DNS 解析。它还可以提供外部名称解析，解析由 CoreDNS 部署管理的任何 DNS 区域的名称。

## 设置外部 DNS

目前，我们的 CoreDNS 只为内部集群名称解析名称，因此我们需要为我们的新 DNS 条目设置一个区域。由于 FooWidgets 希望所有应用程序都进入**foowidgets.k8s**，我们将使用它作为我们的新区域。

## 集成外部 DNS 和 CoreDNS

向我们的集群提供动态服务注册的最后一步是部署并集成**external-dns**与 CoreDNS。

要配置**external-dns**和 CoreDNS 在集群中工作，我们需要配置每个使用 ETCD 的新 DNS 区域。由于我们的集群正在运行预安装的 ETCD 的 KinD，我们将部署一个专用于**external-dns**区域的新 ETCD pod。

部署新 ETCD 服务的最快方法是使用官方 ETCD 操作员 Helm 图表。使用以下单个命令，我们可以安装操作员和一个三节点的 ETCD 集群。

首先，我们需要安装 Helm 二进制文件。我们可以使用 Helm 团队提供的脚本快速安装 Helm：

curl -fsSL -o get_helm.sh https://raw.githubusercontent.com/helm/helm/master/scripts/get-helm-3

chmod 700 get_helm.sh

./get_helm.sh

现在，使用 Helm，我们可以创建与 CoreDNS 集成的 ETCD 集群。以下命令将部署 ETCD 运算符并创建 ETCD 集群：

helm install etcd-dns --set customResources.createEtcdClusterCRD=true stable/etcd-operator --namespace kube-system

部署运算符和 ETCD 节点需要几分钟的时间。您可以通过查看**kube-system**命名空间中的 pod 的状态来检查状态。安装完成后，您将看到三个 ETCD 运算符 pod 和三个 ETCD 集群 pod：

![图 6.13 - ETCD 运算符和节点](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/k8s-dkr/img/Fig_6.13_B15514.jpg)

图 6.13 - ETCD 运算符和节点

部署完成后，查看**kube-system**命名空间中的服务，以获取名为**etcd-cluster-client**的新 ETCD 服务的 IP 地址：

![图 6.14 - ETCD 服务 IP](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/k8s-dkr/img/Fig_6.14_B15514.jpg)

图 6.14 - ETCD 服务 IP

我们将需要分配的 IP 地址来配置**external-dns**和下一节中的 CoreDNS 区文件。

## 向 CoreDNS 添加 ETCD 区域

**external-dns**需要将 CoreDNS 区存储在 ETCD 服务器上。早些时候，我们为 foowidgets 创建了一个新区域，但那只是一个标准区域，需要手动添加新服务的新记录。用户没有时间等待测试他们的部署，并且使用 IP 地址可能会导致代理服务器或内部策略出现问题。为了帮助用户加快其服务的交付和测试，我们需要为他们的服务提供动态名称解析。要为 foowidgets 启用 ETCD 集成区域，请编辑 CoreDNS configmap，并添加以下粗体行。

您可能需要将**端点**更改为在上一页检索到的新 ETCD 服务的 IP 地址：

apiVersion: v1

数据：

Corefile: |

.:53 {

errors

健康 {

lameduck 5s

}

准备

kubernetes cluster.local in-addr.arpa ip6.arpa {

pods insecure

fallthrough in-addr.arpa ip6.arpa

ttl 30

}

prometheus :9153

forward . /etc/resolv.conf

**etcd foowidgets.k8s {**

**stubzones**

**路径/skydns**

**端点 http://10.96.181.53:2379**

**}**

cache 30

循环

重新加载

负载平衡

}

kind: ConfigMap

下一步是将**external-dns**部署到集群中。

我们在 GitHub 存储库的**chapter6**目录中提供了一个清单，该清单将使用您的 ETCD 服务端点修补部署。您可以通过在**chapter6**目录中执行以下命令来使用此清单部署**外部 DNS**。以下命令将查询 ETCD 集群的服务 IP，并使用该 IP 创建一个部署文件作为端点。

然后，新创建的部署将在您的集群中安装**外部 DNS**：

ETCD_URL=$(kubectl -n kube-system get svc etcd-cluster-client -o go-template='{{ .spec.clusterIP }}')

cat external-dns.yaml | sed -E "s/<ETCD_URL>/${ETCD_URL}/" > external-dns-deployment.yaml

kubectl apply -f external-dns-deployment.yaml

要手动将**外部 DNS**部署到您的集群中，请创建一个名为**external-dns-deployment.yaml**的新清单，并在最后一行使用您的 ETCD 服务 IP 地址的以下内容：

apiVersion: rbac.authorization.k8s.io/v1beta1

类型：ClusterRole

元数据：

名称：外部 DNS

规则：

- apiGroups: [""]

资源：["services","endpoints","pods"]

动词：["get","watch","list"]

- apiGroups: ["extensions"]

资源：["ingresses"]

动词：["get","watch","list"]

- apiGroups: [""]

资源：["nodes"]

动词：["list"]

---

apiVersion: rbac.authorization.k8s.io/v1beta1

类型：ClusterRoleBinding

元数据：

名称：外部 DNS 查看器

角色引用：

apiGroup: rbac.authorization.k8s.io

类型：ClusterRole

名称：外部 DNS

主题：

- 类型：ServiceAccount

名称：外部 DNS

命名空间：kube-system

---

apiVersion: v1

类型：ServiceAccount

元数据：

名称：外部 DNS

命名空间：kube-system

---

apiVersion: apps/v1

类型：Deployment

元数据：

名称：外部 DNS

命名空间：kube-system

规范：

策略：

类型：重新创建

选择器：

匹配标签：

应用：外部 DNS

模板：

元数据：

标签：

应用：外部 DNS

规范：

服务账户名称：外部 DNS

容器：

- 名称：外部 DNS

镜像：registry.opensource.zalan.do/teapot/external-dns:latest

参数：

- --source=service

- --provider=coredns

- --log-level=info

环境：

- 名称：ETCD_URLS

值：http://10.96.181.53:2379

请记住，如果您的 ETCD 服务器 IP 地址不是 10.96.181.53，请在部署清单之前更改它。

使用**kubectl apply -f external-dns-deployment.yaml**部署清单。

## 创建具有外部 DNS 集成的负载均衡器服务

您应该仍然拥有本章开头时运行的 NGINX 部署。它有一些与之相关的服务。我们将添加另一个服务，以向您展示如何为部署创建动态注册：

1.  要在 CoreDNS 区域中创建动态条目，您需要在服务清单中添加一个注释。创建一个名为**nginx-dynamic.yaml**的新文件，内容如下：

api 版本：v1

种类：服务

元数据：

**注释：**

**external-dns.alpha.kubernetes.io/hostname: nginx.foowidgets.k8s**

名称：nginx-ext-dns

命名空间：默认

规范：

端口：

- 端口：8080

协议：TCP

目标端口：8080

选择器：

运行：nginx-web

类型：负载均衡器

注意文件中的注释。要指示**external-dns**创建记录，您需要添加一个具有键**external-dns.alpha.kubernetes.io/hostname**的注释，其中包含服务的所需名称 - 在本例中为**nginx.foowidgets.k8s**。

1.  使用**kubectl apply -f nginx-dynamic.yaml**创建服务。

**external-dns**大约需要一分钟来获取 DNS 更改。

1.  要验证记录是否已创建，请使用**kubectl logs -n kube-system -l app=external-dns**检查**external-dns**的 pod 日志。一旦**external-dns**捕获到记录，您将看到类似以下的条目：

**time="2020-04-27T18:14:38Z" level=info msg="Add/set key /skydns/k8s/foowidgets/nginx/03ebf8d8 to Host=172.17.201.101, Text=\"heritage=external-dns,external-dns/owner=default,external-dns/resource=service/default/nginx-lb\", TTL=0"**

1.  确认**external-dns**完全工作的最后一步是测试与应用程序的连接。由于我们使用的是 KinD 集群，我们必须从集群中的一个 pod 进行测试。我们将使用 Netshoot 容器，就像我们在本书中一直在做的那样。

重要提示

在本节的最后，我们将展示将 Windows DNS 服务器与我们的 Kubernetes CoreDNS 服务器集成的步骤。这些步骤旨在让您完全了解如何将企业 DNS 服务器完全集成到我们的 CoreDNS 服务中。

1.  运行 Netshoot 容器：

**kubectl run --generator=run-pod/v1 tmp-shell --rm -i --tty --image nicolaka/netshoot -- /bin/bash**

1.  要确认条目已成功创建，请在 Netshoot shell 中执行**nslookup**以查找主机：![图 6.15 - Nslookup 的新记录](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/k8s-dkr/img/Fig_6.15_B15514.jpg)

图 6.15 - Nslookup 的新记录

我们可以确认正在使用的 DNS 服务器是 CoreDNS，基于 IP 地址，这是分配给**kube-dns**服务的 IP 地址。（再次强调，服务是**kube-dns**，但是 pod 正在运行 CoreDNS）。

172.17.201.101 地址是分配给新 NGINX 服务的 IP 地址；我们可以通过列出默认命名空间中的服务来确认这一点：

![图 6.16 – NGINX 外部 IP 地址](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/k8s-dkr/img/Fig_6.16_B15514.jpg)

图 6.16 – NGINX 外部 IP 地址

1.  最后，让我们通过使用名称连接到容器来确认连接到 NGINX 是否有效。在 Netshoot 容器中使用**curl**命令，curl 到端口 8080 上的 DNS 名称：

![图 6.17 – 使用 external-dns 名称进行 Curl 测试](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/k8s-dkr/img/Fig_6.17_B15514.jpg)

图 6.17 – 使用 external-dns 名称进行 Curl 测试

**curl**输出确认我们可以使用动态创建的服务名称访问 NGINX Web 服务器。

我们意识到其中一些测试并不是非常令人兴奋，因为您可以使用标准浏览器进行测试。在下一节中，我们将把我们集群中运行的 CoreDNS 与 Windows DNS 服务器集成起来。

### 将 CoreDNS 与企业 DNS 集成

本节将向您展示如何将**foowidgets.k8s**区域的名称解析转发到运行在 Kubernetes 集群上的 CoreDNS 服务器。

注意

本节包括了一个示例，演示如何将企业 DNS 服务器与 Kubernetes DNS 服务集成。

由于外部要求和额外的设置，提供的步骤仅供参考，**不应**在您的 KinD 集群上执行。

对于这种情况，主 DNS 服务器运行在 Windows 2016 服务器上。

部署的组件如下：

+   运行 DNS 的 Windows 2016 服务器

+   一个 Kubernetes 集群

+   Bitnami NGINX 部署

+   创建了 LoadBalancer 服务，分配的 IP 为 10.2.1.74

+   CoreDNS 服务配置为使用 hostPort 53

+   部署了附加组件，使用本章的配置，如 external-dns，CoreDNS 的 ETCD 集群，添加了 CoreDNS ETCD 区域，并使用地址池 10.2.1.60-10.2.1.80 的 MetalLB

现在，让我们按照配置步骤来集成我们的 DNS 服务器。

#### 配置主 DNS 服务器

第一步是创建一个有条件的转发器到运行 CoreDNS pod 的节点。

在 Windows DNS 主机上，我们需要为**foowidgets.k8s**创建一个新的有条件的转发器，指向运行 CoreDNS pod 的主机。在我们的示例中，CoreDNS pod 已分配给主机 10.240.100.102：

![图 6.18 - Windows 条件转发器设置](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/k8s-dkr/img/Fig_6.18_B15514.jpg)

图 6.18 - Windows 条件转发器设置

这将配置 Windows DNS 服务器，将对**foowidgets.k8s**域中主机的任何请求转发到 CoreDNS pod。

#### 测试 DNS 转发到 CoreDNS

为了测试配置，我们将使用主网络上已配置为使用 Windows DNS 服务器的工作站。

我们将运行的第一个测试是对 MetalLB 注释创建的 NGINX 记录进行**nslookup**：

从命令提示符中，我们执行**nslookup nginx.foowidgets.k8s**：

![图 6.19 - 注册名称的 Nslookup 确认](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/k8s-dkr/img/Fig_6.19_B15514.jpg)

图 6.19 - 注册名称的 Nslookup 确认

由于查询返回了我们期望的记录的 IP 地址，我们可以确认 Windows DNS 服务器正确地将请求转发到 CoreDNS。

我们可以从笔记本电脑的浏览器进行一次额外的 NGINX 测试：

![图 6.20 - 使用 CoreDNS 从外部工作站成功浏览](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/k8s-dkr/img/Fig_6.20_B15514.jpg)

图 6.20 - 使用 CoreDNS 从外部工作站成功浏览

一个测试确认了转发的工作，但我们不确定系统是否完全正常工作。

为了测试一个新的服务，我们部署了一个名为 microbot 的不同 NGINX 服务器，该服务具有一个注释，分配了名称**microbot.foowidgets.k8s**。MetalLB 已经分配了该服务的 IP 地址为 10.2.1.65。

与之前的测试一样，我们使用 nslookup 测试名称解析：

![图 6.21 - 用于额外注册名称的 Nslookup 确认](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/k8s-dkr/img/Fig_6.21_B15514.jpg)

图 6.21 - 用于额外注册名称的 Nslookup 确认

为了确认 Web 服务器是否正常运行，我们从工作站浏览到 URL：

![图 6.22 - 使用 CoreDNS 从外部工作站成功浏览](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/k8s-dkr/img/Fig_6.22_B15514.jpg)

图 6.22 - 使用 CoreDNS 从外部工作站成功浏览

成功！我们现在已将企业 DNS 服务器与在 Kubernetes 集群上运行的 CoreDNS 服务器集成在一起。这种集成使用户能够通过简单地向服务添加注释来动态注册服务名称。

# 总结

在本章中，您了解了 Kubernetes 中两个重要的对象，这些对象将您的部署暴露给其他集群资源和用户。

我们开始本章时讨论了服务和可以分配的多种类型。三种主要的服务类型是 ClusterIP、NodePort 和 LoadBalancer。选择服务类型将配置应用程序的访问方式。

通常，仅使用服务并不是提供对在集群中运行的应用程序的访问的唯一对象。您通常会使用 ClusterIP 服务以及 Ingress 控制器来提供对使用第 7 层的服务的访问。一些应用程序可能需要额外的通信，第 7 层负载均衡器无法提供这种通信。这些应用程序可能需要第 4 层负载均衡器来向用户公开其服务。在负载均衡部分，我们演示了 MetalLB 的安装和使用，这是一个常用的开源第 7 层负载均衡器。

在最后一节中，我们解释了如何使用条件转发将动态 CoreDNS 区集成到外部企业 DNS 服务器。集成这两个命名系统提供了一种方法，允许在集群中动态注册任何第 4 层负载均衡服务。

现在您知道如何向用户公开集群上的服务，那么我们如何控制谁可以访问集群来创建新服务呢？在下一章中，我们将解释如何将身份验证集成到您的集群中。我们将在我们的 KinD 集群中部署一个 OIDC 提供程序，并与外部 SAML2 实验室服务器连接以获取身份。

# 问题

1.  服务如何知道应该使用哪些 pod 作为服务的端点？

A. 通过服务端口

B. 通过命名空间

C. 由作者

D. 通过选择器标签

1.  哪个 kubectl 命令可以帮助您排除可能无法正常工作的服务？

A. **kubectl get services <service name>**

B. **kubectl get ep <service name>**

C. **kubectl get pods <service name>**

D. **kubectl get servers <service name>**

1.  所有 Kubernetes 发行版都支持使用**LoadBalancer**类型的服务。

A. 真

B. 错误

1.  哪种负载均衡器类型支持所有 TCP/UDP 端口并接受数据包内容？

A. 第 7 层

B. Cisco 层

C. 第 2 层

D. 第 4 层

1.  在没有任何附加组件的情况下，您可以使用以下哪种服务类型来使用多个协议？

A. **NodePort**和**ClusterIP**

B. **LoadBalancer**和**NodePort**

C. **NodePort**、**LoadBalancer**和**ClusterIP**

D. **负载均衡器**和**ClusterIP**
