# Kubernetes 云原生指南（一）

> 原文：[`zh.annas-archive.org/md5/58DD843CC49B42503E619A37722EEB6C`](https://zh.annas-archive.org/md5/58DD843CC49B42503E619A37722EEB6C)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

本书的目的是为您提供构建使用 Kubernetes 的云原生应用程序所需的知识和广泛的工具集。Kubernetes 是一种强大的技术，为工程师提供了强大的工具，以使用容器构建云原生平台。该项目本身不断发展，并包含许多不同的工具来解决常见的场景。

对于本书的布局，我们不会局限于 Kubernetes 工具集的任何一个特定领域，而是首先为您提供默认 Kubernetes 功能的最重要部分的全面摘要，从而为您提供在 Kubernetes 上运行应用程序所需的所有技能。然后，我们将为您提供在第 2 天场景中处理 Kubernetes 安全性和故障排除所需的工具。最后，我们将超越 Kubernetes 本身的界限，探讨一些强大的模式和技术，以构建在 Kubernetes 之上的内容，例如服务网格和无服务器。

# 这本书是为谁准备的

这本书是为初学者准备的，但您应该对容器和 DevOps 原则非常熟悉，以便充分利用本书。对 Linux 有扎实的基础将有所帮助，但并非完全必要。

# 本书涵盖内容

第一章《与 Kubernetes 通信》向您介绍了容器编排的概念以及 Kubernetes 工作原理的基础知识。它还为您提供了与 Kubernetes 集群通信和认证所需的基本工具。

第二章《设置您的 Kubernetes 集群》将指导您通过几种不同的流行方式在本地机器和云上创建 Kubernetes 集群。

第三章《在 Kubernetes 上运行应用程序容器》向您介绍了在 Kubernetes 上运行应用程序的最基本构建块 - Pod。我们将介绍如何创建 Pod，以及 Pod 生命周期的具体内容。

第四章《扩展和部署您的应用程序》回顾了更高级的控制器，这些控制器允许扩展和升级应用程序的多个 Pod，包括自动扩展。

第五章，服务和入口 - 与外部世界通信，介绍了将在 Kubernetes 集群中运行的应用程序暴露给外部用户的几种方法。

第六章，Kubernetes 应用程序配置，为您提供了在 Kubernetes 上运行的应用程序提供配置（包括安全数据）所需的技能。

第七章，Kubernetes 上的存储，回顾了为在 Kubernetes 上运行的应用程序提供持久性和非持久性存储的方法和工具。

第八章，Pod 放置控制，介绍了控制和影响 Kubernetes 节点上 Pod 放置的几种不同工具和策略。

第九章，Kubernetes 上的可观察性，涵盖了在 Kubernetes 上下文中可观察性的多个原则，包括指标、跟踪和日志记录。

第十章，Kubernetes 故障排除，回顾了 Kubernetes 集群可能出现故障的一些关键方式，以及如何有效地对 Kubernetes 上的问题进行分类。

第十一章，Kubernetes 上的模板代码生成和 CI/CD，介绍了 Kubernetes YAML 模板工具和一些常见的 Kubernetes 上的 CI/CD 模式。

第十二章，Kubernetes 安全和合规性，涵盖了 Kubernetes 安全的基础知识，包括 Kubernetes 项目的一些最近的安全问题，以及集群和容器安全的工具。

第十三章，使用 CRD 扩展 Kubernetes，介绍了自定义资源定义（CRD）以及其他向 Kubernetes 添加自定义功能的方法，如操作员。

第十四章，服务网格和无服务器，回顾了 Kubernetes 上的一些高级模式，教您如何向集群添加服务网格并启用无服务器工作负载。

第十五章，Kubernetes 上的有状态工作负载，详细介绍了在 Kubernetes 上运行有状态工作负载的具体内容，包括运行生态系统中一些强大的有状态应用程序的教程。

# 充分利用本书

由于 Kubernetes 基于容器，本书中的一些示例可能使用自出版以来发生了变化的容器。其他说明性示例可能使用在 Docker Hub 中不存在的容器。这些示例应作为运行您自己的应用程序容器的基础。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cld-ntv-k8s/img/Preface_table_1.1.jpg)

在某些情况下，像 Kubernetes 这样的开源软件可能会有重大变化。本书与 Kubernetes 1.19 保持最新，但始终检查文档（对于 Kubernetes 和本书涵盖的任何其他开源项目）以获取最新信息和规格说明。

**如果您使用本书的数字版本，我们建议您自己输入代码或通过 GitHub 存储库（链接在下一节中提供）访问代码。这样做将帮助您避免与复制和粘贴代码相关的任何潜在错误。**

# 下载示例代码文件

您可以从 GitHub 上的[`github.com/PacktPublishing/Cloud-Native-with-Kubernetes`](https://github.com/PacktPublishing/Cloud-Native-with-Kubernetes)下载本书的示例代码文件。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还提供了来自我们丰富书籍和视频目录的其他代码包，可在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)上找到！

# 下载彩色图片

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图像。您可以在这里下载：[`www.packtpub.com/sites/default/files/downloads/9781838823078_ColorImages.pdf`](http://www.packtpub.com/sites/default/files/downloads/9781838823078_ColorImages.pdf)。

# 使用的约定

本书中使用了许多文本约定。

`文本中的代码`：指示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。以下是一个例子：“在我们的情况下，我们希望让集群上的每个经过身份验证的用户创建特权 Pod，因此我们绑定到`system:authenticated`组。”

代码块设置如下：

```
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: full-restriction-policy
  namespace: development
spec:
  policyTypes:
  - Ingress
  - Egress
  podSelector: {}
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```
spec:
  privileged: false
  allowPrivilegeEscalation: false
  volumes:
 - 'configMap'
 - 'emptyDir'
 - 'projected'
 - 'secret'
 - 'downwardAPI'
 - 'persistentVolumeClaim'
  hostNetwork: false
  hostIPC: false
  hostPID: false
```

任何命令行输入或输出都以以下方式编写：

```
helm install falco falcosecurity/falco
```

**粗体**：表示一个新术语，一个重要的词，或者屏幕上看到的词。例如，菜单或对话框中的单词会以这种方式出现在文本中。这是一个例子：“Prometheus 还提供了一个用于配置 Prometheus 警报的**警报**选项卡。”

提示或重要说明

像这样出现。


# 第一部分：设置 Kubernetes

在本节中，您将了解 Kubernetes 的用途，其架构以及与之通信和创建简单集群的基础知识，以及如何运行基本工作负载。

本书的这一部分包括以下章节：

+   *第一章*, *与 Kubernetes 通信*

+   *第二章*, *设置您的 Kubernetes 集群*

+   *第三章*, *在 Kubernetes 上运行应用容器*


# 第一章：与 Kubernetes 通信

本章包含容器编排的解释，包括其优势、用例和流行的实现。我们还将简要回顾 Kubernetes，包括架构组件的布局，以及对授权、身份验证和与 Kubernetes 的一般通信的入门。到本章结束时，您将知道如何对 Kubernetes API 进行身份验证和通信。

在本章中，我们将涵盖以下主题：

+   容器编排入门

+   Kubernetes 的架构

+   在 Kubernetes 上的身份验证和授权

+   使用 kubectl 和 YAML 文件

# 技术要求

为了运行本章详细介绍的命令，您需要一台运行 Linux、macOS 或 Windows 的计算机。本章将教您如何安装`kubectl`命令行工具，您将在以后的所有章节中使用它。

本章中使用的代码可以在书的 GitHub 存储库中找到，链接如下：

[`github.com/PacktPublishing/Cloud-Native-with-Kubernetes/tree/master/Chapter1`](https://github.com/PacktPublishing/Cloud-Native-with-Kubernetes/tree/master/Chapter1)

# 介绍容器编排

谈论 Kubernetes 时，不能不介绍其目的。Kubernetes 是一个容器编排框架，让我们在本书的背景下回顾一下这意味着什么。

## 什么是容器编排？

容器编排是在云端和数据中心运行现代应用程序的流行模式。通过使用容器-预配置的应用程序单元和捆绑的依赖项-作为基础，开发人员可以并行运行许多应用程序实例。

## 容器编排的好处

容器编排提供了许多好处，但我们将重点介绍主要的好处。首先，它允许开发人员轻松构建**高可用性**应用程序。通过运行多个应用程序实例，容器编排系统可以配置成自动替换任何失败的应用程序实例为新的实例。

这可以通过在物理数据中心中分散应用程序的多个实例来扩展到云端，因此如果一个数据中心崩溃，应用程序的其他实例将保持运行，并防止停机。

其次，容器编排允许高度**可扩展**的应用程序。由于可以轻松创建和销毁应用程序的新实例，编排工具可以自动扩展以满足需求。在云环境或数据中心环境中，可以向编排工具添加新的**虚拟机**（**VMs**）或物理机，以提供更大的计算资源池。在云环境中，这个过程可以完全自动化，实现完全无需人工干预的扩展，无论是在微观还是宏观层面。

## 流行的编排工具

生态系统中有几种非常流行的容器编排工具：

+   **Docker Swarm**：Docker Swarm 是由 Docker 容器引擎团队创建的。与 Kubernetes 相比，它更容易设置和运行，但相对灵活性较差。

+   **Apache Mesos**：Apache Mesos 是一个较低级别的编排工具，可以管理数据中心和云环境中的计算、内存和存储。默认情况下，Mesos 不管理容器，但是 Marathon - 一个在 Mesos 之上运行的框架 - 是一个完全成熟的容器编排工具。甚至可以在 Mesos 之上运行 Kubernetes。

+   **Kubernetes**：截至 2020 年，容器编排工作大部分集中在 Kubernetes（koo-bur-net-ees）周围，通常缩写为 k8s。Kubernetes 是一个开源容器编排工具，最初由谷歌创建，借鉴了谷歌多年来在内部编排工具 Borg 和 Omega 的经验。自 Kubernetes 成为开源项目以来，它已经成为企业环境中运行和编排容器的事实标准。其中一些原因包括 Kubernetes 是一个成熟的产品，拥有一个非常庞大的开源社区。它比 Mesos 更容易操作，比 Docker Swarm 更灵活。

从这个比较中最重要的一点是，尽管容器编排有多个相关选项，而且在某些方面确实更好，但 Kubernetes 已经成为事实标准。有了这个认识，让我们来看看 Kubernetes 是如何工作的。

# Kubernetes 的架构

Kubernetes 是一个可以在云虚拟机上运行的编排工具，也可以在数据中心的虚拟机或裸机服务器上运行。一般来说，Kubernetes 在一组节点上运行，每个节点可以是虚拟机或物理机。

## Kubernetes 节点类型

Kubernetes 节点可以是许多不同的东西-从虚拟机到裸金属主机再到树莓派。Kubernetes 节点分为两个不同的类别：首先是主节点，运行 Kubernetes 控制平面应用程序；其次是工作节点，运行您部署到 Kubernetes 上的应用程序。

一般来说，为了实现高可用性，Kubernetes 的生产部署应该至少有三个主节点和三个工作节点，尽管大多数大型部署的工作节点比主节点多得多。

## Kubernetes 控制平面

Kubernetes 控制平面是一套运行在主节点上的应用程序和服务。有几个高度专业化的服务在发挥作用，构成了 Kubernetes 功能的核心。它们如下：

+   kube-apiserver：这是 Kubernetes API 服务器。该应用程序处理发送到 Kubernetes 的指令。

+   kube-scheduler：这是 Kubernetes 调度程序。该组件处理决定将工作负载放置在哪些节点上的工作，这可能变得非常复杂。

+   kube-controller-manager：这是 Kubernetes 控制器管理器。该组件提供了一个高级控制循环，确保集群的期望配置和运行在其上的应用程序得到实施。

+   etcd：这是一个包含集群配置的分布式键值存储。

一般来说，所有这些组件都采用系统服务的形式，在每个主节点上运行。如果您想完全手动引导集群，可以手动启动它们，但是通过使用集群创建库或云提供商管理的服务，例如**弹性 Kubernetes 服务（EKS）**，在生产环境中通常会自动完成这些操作。

## Kubernetes API 服务器

Kubernetes API 服务器是一个接受 HTTPS 请求的组件，通常在端口`443`上。它提供证书，可以是自签名的，以及身份验证和授权机制，我们将在本章后面介绍。

当对 Kubernetes API 服务器进行配置请求时，它将检查`etcd`中的当前集群配置，并在必要时进行更改。

Kubernetes API 通常是一个 RESTful API，每个 Kubernetes 资源类型都有端点，以及在查询路径中传递的 API 版本；例如，`/api/v1`。

为了扩展 Kubernetes（参见[*第十三章*]（B14790_13_Final_PG_ePub.xhtml#_idTextAnchor289），*使用 CRD 扩展 Kubernetes*），API 还具有一组基于 API 组的动态端点，可以向自定义资源公开相同的 RESTful API 功能。

## Kubernetes 调度程序

Kubernetes 调度程序决定工作负载的实例应该在哪里运行。默认情况下，此决定受工作负载资源要求和节点状态的影响。您还可以通过 Kubernetes 中可配置的放置控件来影响调度程序（参见[*第八章*]（B14790_08_Final_PG_ePub.xhtml#_idTextAnchor186），*Pod 放置控件*）。这些控件可以作用于节点标签，其他 Pod 已经在节点上运行的情况，以及许多其他可能性。

## Kubernetes 控制器管理器

Kubernetes 控制器管理器是运行多个控制器的组件。控制器运行控制循环，确保集群的实际状态与配置中存储的状态匹配。默认情况下，这些包括以下内容：

+   节点控制器，确保节点正常运行

+   复制控制器，确保每个工作负载被适当地扩展

+   端点控制器，处理每个工作负载的通信和路由配置（参见[*第五章*]（B14790_05_Final_PG_ePub.xhtml#_idTextAnchor127）*，服务和入口 - 与外部世界通信*）

+   服务帐户和令牌控制器，处理 API 访问令牌和默认帐户的创建

## etcd

etcd 是一个分布式键值存储，以高可用的方式存储集群的配置。每个主节点上都运行一个`etcd`副本，并使用 Raft 一致性算法，确保在允许对键或值进行任何更改之前保持法定人数。

## Kubernetes 工作节点

每个 Kubernetes 工作节点都包含允许其与控制平面通信和处理网络的组件。

首先是**kubelet**，它确保容器根据集群配置在节点上运行。其次，**kube-proxy**为在每个节点上运行的工作负载提供网络代理层。最后，**容器运行时**用于在每个节点上运行工作负载。

## kubelet

kubelet 是在每个节点上运行的代理程序（包括主节点，尽管在该上下文中它具有不同的配置）。它的主要目的是接收 PodSpecs 的列表（稍后会详细介绍），并确保它们所规定的容器在节点上运行。kubelet 通过几种不同的可能机制获取这些 PodSpecs，但主要方式是通过查询 Kubernetes API 服务器。另外，kubelet 可以通过文件路径启动，它将监视 PodSpecs 的列表，监视 HTTP 端点，或者在其自己的 HTTP 端点上接收请求。

## kube-proxy

kube-proxy 是在每个节点上运行的网络代理。它的主要目的是对其节点上运行的工作负载进行 TCP、UDP 和 SCTP 转发（通过流或轮询）。kube-proxy 支持 Kubernetes 的`Service`构造，我们将在*第五章**，服务和入口 - 与外部世界通信*中讨论。

## 容器运行时

容器运行时在每个节点上运行，它实际上运行您的工作负载。Kubernetes 支持 CRI-O、Docker、containerd、rktlet 和任何有效的**容器运行时接口**（**CRI**）运行时。从 Kubernetes v1.14 开始，RuntimeClass 功能已从 alpha 版移至 beta 版，并允许特定于工作负载的运行时选择。

## 插件

除了核心集群组件外，典型的 Kubernetes 安装包括插件，这些是提供集群功能的附加组件。

例如，**容器网络接口**（**CNI**）插件，如`Calico`、`Flannel`或`Weave`，提供符合 Kubernetes 网络要求的覆盖网络功能。

另一方面，CoreDNS 是一个流行的插件，用于集群内的 DNS 和服务发现。还有一些工具，比如 Kubernetes Dashboard，它提供了一个 GUI，用于查看和与您的集群进行交互。

到目前为止，您应该对 Kubernetes 的主要组件有一个高层次的了解。接下来，我们将回顾用户如何与 Kubernetes 交互以控制这些组件。

# Kubernetes 上的身份验证和授权

命名空间是 Kubernetes 中一个非常重要的概念，因为它们可以影响 API 访问以及授权，我们现在将介绍它们。

## 命名空间

Kubernetes 中的命名空间是一种构造，允许您在集群中对 Kubernetes 资源进行分组。它们是一种分离的方法，有许多可能的用途。例如，您可以在集群中为每个环境（开发、暂存和生产）创建一个命名空间。

默认情况下，Kubernetes 将创建默认命名空间、`kube-system`命名空间和`kube-public`命名空间。在未指定命名空间的情况下创建的资源将在默认命名空间中创建。`kube-system`包含集群服务，如`etcd`、调度程序以及 Kubernetes 本身创建的任何资源，而不是用户创建的资源。`kube-public`默认情况下可被所有用户读取，并且可用于公共资源。

## 用户

Kubernetes 中有两种类型的用户 - 常规用户和服务帐户。

通常由集群外的服务管理常规用户，无论是私钥、用户名和密码，还是某种用户存储形式。但是，服务帐户由 Kubernetes 管理，并且受限于特定的命名空间。要创建服务帐户，Kubernetes API 可能会自动创建一个，或者可以通过调用 Kubernetes API 手动创建。

Kubernetes API 有三种可能的请求类型 - 与常规用户关联的请求，与服务帐户关联的请求和匿名请求。

## 认证方法

为了对请求进行身份验证，Kubernetes 提供了几种不同的选项：HTTP 基本身份验证、客户端证书、bearer 令牌和基于代理的身份验证。

要使用 HTTP 身份验证，请求者发送带有`Authorization`头的请求，其值为 bearer `"token value"`。

为了指定哪些令牌是有效的，可以在 API 服务器应用程序启动时使用`--token-auth-file=filename`参数提供一个 CSV 文件。一个新的测试功能（截至本书撰写时），称为*引导令牌*，允许在 API 服务器运行时动态交换和更改令牌，而无需重新启动它。

还可以通过`Authorization`令牌进行基本的用户名/密码身份验证，方法是使用头部值`Basic base64encoded(username:password)`。

## Kubernetes 的 TLS 和安全证书基础设施

为了使用客户端证书（X.509 证书），API 服务器必须使用`--client-ca-file=filename`参数启动。该文件需要包含一个或多个用于验证通过 API 请求传递的证书的**证书颁发机构**（**CAs**）。

除了**CA**之外，必须为每个用户创建一个**证书签名请求**（**CSR**）。在这一点上，可以包括用户`groups`，我们将在*授权*选项部分讨论。

例如，您可以使用以下内容：

```
openssl req -new -key myuser.pem -out myusercsr.pem -subj "/CN=myuser/0=dev/0=staging"
```

这将为名为`myuser`的用户创建一个 CSR，该用户属于名为`dev`和`staging`的组。

创建 CA 和 CSR 后，可以使用`openssl`、`easyrsa`、`cfssl`或任何证书生成工具创建实际的客户端和服务器证书。此时还可以创建用于 Kubernetes API 的 TLS 证书。

由于我们的目标是尽快让您开始在 Kubernetes 上运行工作负载，我们将不在本书中涉及各种可能的证书配置 - 但 Kubernetes 文档和文章* Kubernetes The Hard Way*都有一些关于从头开始设置集群的很棒的教程。在大多数生产环境中，您不会手动执行这些步骤。

## 授权选项

Kubernetes 提供了几种授权方法：节点、webhooks、RBAC 和 ABAC。在本书中，我们将重点关注 RBAC 和 ABAC，因为它们是用户授权中最常用的方法。如果您通过其他服务和/或自定义功能扩展了集群，则其他授权模式可能变得更加重要。

## RBAC

**RBAC**代表**基于角色的访问控制**，是一种常见的授权模式。在 Kubernetes 中，RBAC 的角色和用户使用四个 Kubernetes 资源来实现：`Role`、`ClusterRole`、`RoleBinding`和`ClusterRoleBinding`。要启用 RBAC 模式，API 服务器可以使用`--authorization-mode=RBAC`参数启动。

`Role`和`ClusterRole`资源指定了一组权限，但不会将这些权限分配给任何特定的用户。权限使用`resources`和`verbs`来指定。以下是一个指定`Role`的示例 YAML 文件。不要太担心 YAML 文件的前几行 - 我们很快就会涉及到这些内容。专注于`resources`和`verbs`行，以了解如何将操作应用于资源：

只读角色.yaml

```
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: default
  name: read-only-role
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list"]
```

`Role` 和 `ClusterRole` 之间唯一的区别是，`Role` 限定于特定的命名空间（在本例中是默认命名空间），而 `ClusterRole` 可以影响集群中该类型的所有资源的访问，以及集群范围的资源，如节点。

`RoleBinding` 和 `ClusterRoleBinding` 是将 `Role` 或 `ClusterRole` 与用户或用户列表关联的资源。以下文件表示一个 `RoleBinding` 资源，将我们的 `read-only-role` 与用户 `readonlyuser` 连接起来：

只读-rb.yaml

```
apiVersion: rbac.authorization.k8s.io/v1namespace.
kind: RoleBinding
metadata:
  name: read-only
  namespace: default
subjects:
- kind: User
  name: readonlyuser
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: Role
  name: read-only-role
  apiGroup: rbac.authorization.k8s.io
```

`subjects` 键包含要将角色与的所有实体的列表；在本例中是用户 `alex`。`roleRef` 包含要关联的角色的名称和类型（`Role` 或 `ClusterRole`）。

## ABAC

**ABAC** 代表 **基于属性的访问控制**。ABAC 使用 *策略* 而不是角色。API 服务器在 ABAC 模式下启动，使用一个称为授权策略文件的文件，其中包含一个名为策略对象的 JSON 对象列表。要启用 ABAC 模式，API 服务器可以使用 `--authorization-mode=ABAC` 和 `--authorization-policy-file=filename` 参数启动。

在策略文件中，每个策略对象包含有关单个策略的信息：首先，它对应的主体，可以是用户或组，其次，可以通过策略访问哪些资源。此外，可以包括一个布尔值 `readonly`，以限制策略仅限于 `list`、`get` 和 `watch` 操作。

与资源关联的第二种类型的策略与非资源请求类型相关联，例如对 `/version` 端点的调用。

当在 ABAC 模式下对 API 发出请求时，API 服务器将检查用户及其所属的任何组是否与策略文件中的列表匹配，并查看是否有任何策略与用户正在尝试访问的资源或端点匹配。匹配时，API 服务器将授权请求。

现在您应该对 Kubernetes API 如何处理身份验证和授权有了很好的理解。好消息是，虽然您可以直接访问 API，但 Kubernetes 提供了一个出色的命令行工具，可以简单地进行身份验证并发出 Kubernetes API 请求。

# 使用 kubectl 和 YAML

kubectl 是官方支持的命令行工具，用于访问 Kubernetes API。它可以安装在 Linux、macOS 或 Windows 上。

## 设置 kubectl 和 kubeconfig

要安装最新版本的 kubectl，可以使用[`kubernetes.io/docs/tasks/tools/install-kubectl/`](https://kubernetes.io/docs/tasks/tools/install-kubectl/)上的安装说明。

安装了 kubectl 之后，需要设置身份验证以与一个或多个集群进行身份验证。这是使用`kubeconfig`文件完成的，其外观如下：

示例-kubeconfig

```
apiVersion: v1
kind: Config
preferences: {}
clusters:
- cluster:
    certificate-authority: fake-ca-file
    server: https://1.2.3.4
  name: development
users:
- name: alex
  user:
    password: mypass
    username: alex
contexts:
- context:
    cluster: development
    namespace: frontend
    user: developer
  name: development
```

该文件以 YAML 编写，与我们即将介绍的其他 Kubernetes 资源规范非常相似 - 只是该文件仅驻留在您的本地计算机上。

`Kubeconfig` YAML 文件有三个部分：`clusters`，`users`和`contexts`：

+   `clusters`部分是您可以通过 kubectl 访问的集群列表，包括 CA 文件名和服务器 API 端点。

+   `users`部分列出了您可以授权的用户，包括用于身份验证的任何用户证书或用户名/密码组合。

+   最后，`contexts`部分列出了集群、命名空间和用户的组合，这些组合形成一个上下文。使用`kubectl config use-context`命令，您可以轻松地在上下文之间切换，从而实现集群、用户和命名空间组合的轻松切换。

## 命令式与声明式命令

与 Kubernetes API 交互有两种范式：命令式和声明式。命令式命令允许您向 Kubernetes“指示要做什么” - 也就是说，“启动两个 Ubuntu 副本”，“将此应用程序扩展到五个副本”等。

另一方面，声明式命令允许您编写一个文件，其中包含应在集群上运行的规范，并且 Kubernetes API 确保配置与集群配置匹配，并在必要时进行更新。

尽管命令式命令允许您快速开始使用 Kubernetes，但最好在运行生产工作负载或任何复杂工作负载时编写一些 YAML 并使用声明性配置。原因是这样做可以更容易地跟踪更改，例如通过 GitHub 存储库，或者向您的集群引入基于 Git 的持续集成/持续交付（CI/CD）。

一些基本的 kubectl 命令

kubectl 提供了许多方便的命令来检查集群的当前状态，查询资源并创建新资源。 kubectl 的结构使大多数命令可以以相同的方式访问资源。

首先，让我们学习如何查看集群中的 Kubernetes 资源。您可以使用`kubectl get resource_type`来执行此操作，其中`resource_type`是 Kubernetes 资源的完整名称，或者是一个更短的别名。别名（和`kubectl`命令）的完整列表可以在 kubectl 文档中找到：[`kubernetes.io/docs/reference/kubectl/overview`](https://kubernetes.io/docs/reference/kubectl/overview)。

我们已经了解了节点，所以让我们从那里开始。要查找集群中存在哪些节点，我们可以使用`kubectl get nodes`或别名`kubectl get no`。

kubectl 的`get`命令返回当前集群中的 Kubernetes 资源列表。我们可以使用任何 Kubernetes 资源类型运行此命令。要向列表添加附加信息，可以添加`wide`输出标志：`kubectl get nodes -o wide`。

列出资源是不够的，当然 - 我们需要能够查看特定资源的详细信息。为此，我们使用`describe`命令，它的工作方式类似于`get`，只是我们可以选择传递特定资源的名称。如果省略了最后一个参数，Kubernetes 将返回该类型所有资源的详细信息，这可能会导致终端中大量的滚动。

例如，`kubectl describe nodes`将返回集群中所有节点的详细信息，而`kubectl describe nodes node1`将返回名为`node1`的节点的描述。

您可能已经注意到，这些命令都是命令式风格的，这是有道理的，因为我们只是获取有关现有资源的信息，而不是创建新资源。要创建 Kubernetes 资源，我们可以使用以下命令：

+   `kubectl create -f /path/to/file.yaml`，这是一个命令式命令

+   `kubectl apply -f /path/to/file.yaml`，这是声明式的

这两个命令都需要一个文件路径，可以是 YAML 或 JSON 格式，或者您也可以使用 `stdin`。您还可以传递文件夹的路径，而不是文件的路径，这将创建或应用该文件夹中的所有 YAML 或 JSON 文件。`create` 是命令式的，因此它将创建一个新的资源，但如果您再次运行它并使用相同的文件，命令将失败，因为资源已经存在。`apply` 是声明性的，因此如果您第一次运行它，它将创建资源，而后续运行将使用任何更改更新 Kubernetes 中正在运行的资源。您可以使用 `--dry-run` 标志来查看 `create` 或 `apply` 命令的输出（即将创建的资源，或者如果存在错误的话）。

要以命令式方式更新现有资源，可以使用 `edit` 命令，如：`kubectl edit resource_type resource_name` – 就像我们的 `describe` 命令一样。这将打开默认的终端编辑器，并显示现有资源的 YAML，无论您是以命令式还是声明式方式创建的。您可以编辑并保存，这将触发 Kubernetes 中资源的自动更新。

要以声明性方式更新现有资源，可以编辑您用于首次创建资源的本地 YAML 资源文件，然后运行 `kubectl apply -f /path/to/file.yaml`。最好通过命令式命令 `kubectl delete resource_type resource_name` 来删除资源。

我们将在本节讨论的最后一个命令是 `kubectl cluster-info`，它将显示主要 Kubernetes 集群服务运行的 IP 地址。

## 编写 Kubernetes 资源 YAML 文件

用于与 Kubernetes API 声明性通信的格式包括 YAML 和 JSON。为了本书的目的，我们将坚持使用 YAML，因为它更清晰，占用页面空间更少。典型的 Kubernetes 资源 YAML 文件如下：

resource.yaml

```
apiVersion: v1
kind: Pod
metadata:
  name: my-pod
spec:
  containers:
  - name: ubuntu
    image: ubuntu:trusty
    command: ["echo"]
    args: ["Hello Readers"]
```

有效的 Kubernetes YAML 文件至少有四个顶级键。它们是 `apiVersion`、`kind`、`metadata` 和 `spec`。

`apiVersion`决定将使用哪个版本的 Kubernetes API 来创建资源。`kind`指定 YAML 文件引用的资源类型。`metadata`提供了一个位置来命名资源，以及添加注释和命名空间信息（稍后会详细介绍）。最后，`spec`键将包含 Kubernetes 创建资源所需的所有特定于资源的信息。

不要担心`kind`和`spec`，我们将在*第三章*中介绍`Pod`是什么，*在 Kubernetes 上运行应用容器*。

# 总结

在本章中，我们学习了容器编排背后的背景，Kubernetes 集群的架构概述，集群如何对 API 调用进行身份验证和授权，以及如何使用 kubectl 以命令和声明模式与 API 进行通信，kubectl 是 Kubernetes 的官方支持的命令行工具。

在下一章中，我们将学习几种启动测试集群的方法，并掌握到目前为止学到的 kubectl 命令。

# 问题

1.  什么是容器编排？

1.  Kubernetes 控制平面的组成部分是什么，它们的作用是什么？

1.  如何启动处于 ABAC 授权模式的 Kubernetes API 服务器？

1.  为什么对于生产 Kubernetes 集群来说拥有多个主节点很重要？

1.  `kubectl apply`和`kubectl create`之间有什么区别？

1.  如何使用`kubectl`在上下文之间切换？

1.  以声明方式创建 Kubernetes 资源然后以命令方式进行编辑的缺点是什么？

# 进一步阅读

+   官方 Kubernetes 文档：[`kubernetes.io/docs/home/`](https://kubernetes.io/docs/home/)

+   *Kubernetes The Hard Way*：[`github.com/kelseyhightower/kubernetes-the-hard-way`](https://github.com/kelseyhightower/kubernetes-the-hard-way)


# 第二章：设置您的 Kubernetes 集群

本章包含了创建 Kubernetes 集群的一些可能性的审查，这将使我们能够学习本书中其余概念所需的知识。我们将从 minikube 开始，这是一个创建简单本地集群的工具，然后涉及一些其他更高级（且适用于生产）的工具，并审查来自公共云提供商的主要托管 Kubernetes 服务，最后介绍从头开始创建集群的策略。

在本章中，我们将涵盖以下主题：

+   创建您的第一个集群的选项

+   minikube – 一个简单的开始方式

+   托管服务 – EKS、GKE、AKS 等

+   Kubeadm – 简单的一致性

+   Kops – 基础设施引导

+   Kubespray – 基于 Ansible 的集群创建

+   完全从头开始创建集群

# 技术要求

为了在本章中运行命令，您需要安装 kubectl 工具。安装说明可在*第一章*，*与 Kubernetes 通信*中找到。

如果您确实要使用本章中的任何方法创建集群，您需要查看相关项目文档中每种方法的具体技术要求。对于 minikube，大多数运行 Linux、macOS 或 Windows 的计算机都可以工作。对于大型集群，请查阅您计划使用的工具的具体文档。

本章中使用的代码可以在书籍的 GitHub 存储库中找到，链接如下：

[`github.com/PacktPublishing/Cloud-Native-with-Kubernetes/tree/master/Chapter2`](https://github.com/PacktPublishing/Cloud-Native-with-Kubernetes/tree/master/Chapter2)

# 创建集群的选项

有许多方法可以创建 Kubernetes 集群，从简单的本地工具到完全从头开始创建集群。

如果您刚开始学习 Kubernetes，可能希望使用 minikube 等工具快速启动一个简单的本地集群。

如果您希望为应用程序构建生产集群，您有几个选项：

+   您可以使用 Kops、Kubespray 或 Kubeadm 等工具以编程方式创建集群。

+   您可以使用托管的 Kubernetes 服务。

+   您可以在虚拟机或物理硬件上完全从头开始创建集群。

除非您在集群配置方面有极其特定的需求（即使是这样），通常不建议完全不使用引导工具从头开始创建您的集群。

对于大多数用例，决策将在使用云提供商上的托管 Kubernetes 服务和使用引导工具之间进行。

在空气隔离系统中，使用引导工具是唯一的选择，但对于特定的用例，有些引导工具比其他引导工具更好。特别是，Kops 旨在使在云提供商（如 AWS）上创建和管理集群变得更容易。

重要提示

本节未包括讨论替代的第三方托管服务或集群创建和管理工具，如 Rancher 或 OpenShift。在选择在生产环境中运行集群时，重要的是要考虑包括当前基础设施、业务需求等在内的各种因素。为了简化问题，在本书中，我们将专注于生产集群，假设没有其他基础设施或超特定的业务需求——可以说是一个“白板”。

# minikube-开始的简单方法

minikube 是开始使用简单本地集群的最简单方法。这个集群不会设置为高可用性，并且不针对生产使用，但这是一个在几分钟内开始在 Kubernetes 上运行工作负载的好方法。

## 安装 minikube

minikube 可以安装在 Windows、macOS 和 Linux 上。接下来是三个平台的安装说明，您也可以通过导航到[`minikube.sigs.k8s.io/docs/start`](https://minikube.sigs.k8s.io/docs/start)找到。

### 在 Windows 上安装

在 Windows 上最简单的安装方法是从[`storage.googleapis.com/minikube/releases/latest/minikube-installer.exe`](https://storage.googleapis.com/minikube/releases/latest/minikube-installer.exe)下载并运行 minikube 安装程序。

### 在 macOS 上安装

使用以下命令下载和安装二进制文件。您也可以在代码存储库中找到它：

Minikube-install-mac.sh

```
     curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-darwin-amd64 \
&& sudo install minikube-darwin-amd64 /usr/local/bin/minikube
```

### 在 Linux 上安装

使用以下命令下载和安装二进制文件：

Minikube-install-linux.sh

```
curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64 \
&& sudo install minikube-linux-amd64 /usr/local/bin/minikube
```

## 在 minikube 上创建一个集群

使用 minikube 创建一个集群，只需运行`minikube start`，这将使用默认的 VirtualBox VM 驱动程序创建一个简单的本地集群。minikube 还有一些额外的配置选项，可以在文档站点上查看。

运行`minikube` `start`命令将自动配置您的`kubeconfig`文件，这样您就可以在新创建的集群上运行`kubectl`命令，而无需进行进一步的配置。

# 托管 Kubernetes 服务

提供托管 Kubernetes 服务的云提供商数量不断增加。然而，对于本书的目的，我们将专注于主要的公共云及其特定的 Kubernetes 服务。这包括以下内容：

+   亚马逊网络服务（AWS） - 弹性 Kubernetes 服务（EKS）

+   谷歌云 - 谷歌 Kubernetes 引擎（GKE）

+   微软 Azure - Azure Kubernetes 服务（AKS）

重要提示

托管 Kubernetes 服务的数量和实施方式总是在变化。AWS、谷歌云和 Azure 被选为本书的这一部分，因为它们很可能会继续以相同的方式运行。无论您使用哪种托管服务，请确保查看服务提供的官方文档，以确保集群创建过程与本书中所呈现的相同。

## 托管 Kubernetes 服务的好处

一般来说，主要的托管 Kubernetes 服务提供了一些好处。首先，我们正在审查的这三个托管服务提供了完全托管的 Kubernetes 控制平面。

这意味着当您使用这些托管 Kubernetes 服务之一时，您不需要担心主节点。它们被抽象化了，可能根本不存在。这三个托管集群都允许您在创建集群时选择工作节点的数量。

托管集群的另一个好处是从一个 Kubernetes 版本无缝升级到另一个版本。一般来说，一旦验证了托管服务的新版本 Kubernetes（不一定是最新版本），您应该能够使用一个按钮或一个相当简单的过程进行升级。

## 托管 Kubernetes 服务的缺点

尽管托管 Kubernetes 集群在许多方面可以简化操作，但也存在一些缺点。

对于许多可用的托管 Kubernetes 服务，托管集群的最低成本远远超过手动创建或使用诸如 Kops 之类的工具创建的最小集群的成本。对于生产用例，这通常不是一个问题，因为生产集群应该包含最少数量的节点，但对于开发环境或测试集群，根据预算，额外的成本可能不值得操作的便利。

此外，虽然抽象化主节点使操作更容易，但它也阻止了对已定义主节点的集群可能可用的精细调整或高级主节点功能。

# AWS - 弹性 Kubernetes 服务

AWS 的托管 Kubernetes 服务称为 EKS，或弹性 Kubernetes 服务。有几种不同的方式可以开始使用 EKS，但我们将介绍最简单的方式。

## 入门

要创建一个 EKS 集群，您必须配置适当的**虚拟私有云（VPC）**和**身份和访问管理（IAM）**角色设置 - 在这一点上，您可以通过控制台创建一个集群。这些设置可以通过控制台手动创建，也可以通过基础设施配置工具如 CloudFormation 和 Terraform 创建。有关通过控制台创建集群的完整说明，请参阅[`docs.aws.amazon.com/en_pv/eks/latest/userguide/getting-started-console.html`](https://docs.aws.amazon.com/en_pv/eks/latest/userguide/getting-started-console.html)。

假设您是从头开始创建集群和 VPC，您可以使用一个名为`eksctl`的工具来配置您的集群。

要安装`eksctl`，您可以在[`docs.aws.amazon.com/eks/latest/userguide/getting-started-eksctl.html`](https://docs.aws.amazon.com/eks/latest/userguide/getting-started-eksctl.html)找到 macOS、Linux 和 Windows 的安装说明。

一旦安装了`eksctl`，创建一个集群就像使用`eksctl create cluster`命令一样简单：

Eks-create-cluster.sh

```
eksctl create cluster \
--name prod \
--version 1.17 \
--nodegroup-name standard-workers \
--node-type t2.small \
--nodes 3 \
--nodes-min 1 \
--nodes-max 4 \
--node-ami auto
```

这将创建一个由三个`t2.small`实例组成的集群，这些实例被设置为一个具有一个节点最小和四个节点最大的自动缩放组。使用的 Kubernetes 版本将是`1.17`。重要的是，`eksctl`从一个默认区域开始，并根据选择的节点数量，在该区域的多个可用区中分布它们。

`eksctl`还将自动更新您的`kubeconfig`文件，因此在集群创建过程完成后，您应该能够立即运行`kubectl`命令。

使用以下代码测试配置：

```
kubectl get nodes
```

您应该看到您的节点及其关联的 IP 列表。您的集群已准备就绪！接下来，让我们看看 Google 的 GKE 设置过程。

# Google Cloud – Google Kubernetes Engine

GKE 是 Google Cloud 的托管 Kubernetes 服务。使用 gcloud 命令行工具，可以很容易地快速启动 GKE 集群。

## 入门

要使用 gcloud 在 GKE 上创建集群，可以使用 Google Cloud 的 Cloud Shell 服务，也可以在本地运行命令。如果要在本地运行命令，必须通过 Google Cloud SDK 安装 gcloud CLI。有关安装说明，请参阅[`cloud.google.com/sdk/docs/quickstarts`](https://cloud.google.com/sdk/docs/quickstarts)。

安装了 gcloud 后，您需要确保已在 Google Cloud 帐户中激活了 GKE API。

要轻松实现这一点，请转到[`console.cloud.google.com/apis/library`](https://console.cloud.google.com/apis/library)，然后在搜索栏中搜索`kubernetes`。单击**Kubernetes Engine API**，然后单击**启用**。

现在 API 已激活，请使用以下命令在 Google Cloud 中设置您的项目和计算区域：

```
gcloud config set project proj_id
gcloud config set compute/zone compute_zone
```

在命令中，`proj_id`对应于您想要在 Google Cloud 中创建集群的项目 ID，`compute_zone`对应于您在 Google Cloud 中期望的计算区域。

实际上，GKE 上有三种类型的集群，每种类型具有不同（增加）的可靠性和容错能力：

+   单区集群

+   多区集群

+   区域集群

GKE 中的**单区**集群意味着具有单个控制平面副本和一个或多个在同一 Google Cloud 区域运行的工作节点的集群。如果区域发生故障，控制平面和工作节点（因此工作负载）都将宕机。

GKE 中的**多区**集群意味着具有单个控制平面副本和两个或多个在不同的 Google Cloud 区域运行的工作节点的集群。这意味着如果单个区域（甚至包含控制平面的区域）发生故障，集群中运行的工作负载仍将持续存在，但是直到控制平面区域恢复之前，Kubernetes API 将不可用。

最后，在 GKE 中，**区域集群** 意味着具有多区域控制平面和多区域工作节点的集群。如果任何区域出现故障，控制平面和工作节点上的工作负载将持续存在。这是最昂贵和可靠的选项。

现在，要实际创建您的集群，您可以运行以下命令以使用默认设置创建名为 `dev` 的集群：

```
gcloud container clusters create dev \
    --zone [compute_zone]
```

此命令将在您选择的计算区域创建一个单区域集群。

为了创建一个多区域集群，您可以运行以下命令：

```
gcloud container clusters create dev \
    --zone [compute_zone_1]
    --node-locations [compute_zone_1],[compute_zone_2],[etc]
```

在这里，`compute_zone_1` 和 `compute_zone_2` 是不同的 Google Cloud 区域。此外，可以通过 `node-locations` 标志添加更多区域。

最后，要创建一个区域集群，您可以运行以下命令：

```
gcloud container clusters create dev \
    --region [region] \
    --node-locations [compute_zone_1],[compute_zone_2],[etc]
```

在这种情况下，`node-locations` 标志实际上是可选的。如果省略，集群将在该区域内的所有区域中创建工作节点。如果您想更改此默认行为，可以使用 `node-locations` 标志进行覆盖。

现在您已经运行了一个集群，需要配置您的 `kubeconfig` 文件以与集群通信。为此，只需将集群名称传递给以下命令：

```
gcloud container clusters get-credentials [cluster_name]
```

最后，使用以下命令测试配置：

```
kubectl get nodes
```

与 EKS 一样，您应该看到所有已配置节点的列表。成功！最后，让我们来看看 Azure 的托管服务。

# Microsoft Azure – Azure Kubernetes 服务

Microsoft Azure 的托管 Kubernetes 服务称为 AKS。可以通过 Azure CLI 在 AKS 上创建集群。

## 入门

要在 AKS 上创建集群，可以使用 Azure CLI 工具，并运行以下命令以创建服务主体（集群将使用该服务主体访问 Azure 资源的角色）：

```
az ad sp create-for-rbac --skip-assignment --name myClusterPrincipal
```

此命令的结果将是一个包含有关服务主体信息的 JSON 对象，我们将在下一步中使用。此 JSON 对象如下所示：

```
{
  "appId": "559513bd-0d99-4c1a-87cd-851a26afgf88",
  "displayName": "myClusterPrincipal",
  "name": "http://myClusterPrincipal",
  "password": "e763725a-5eee-892o-a466-dc88d980f415",
  "tenant": "72f988bf-90jj-41af-91ab-2d7cd011db48"
}
```

现在，您可以使用上一个 JSON 命令中的值来实际创建您的 AKS 集群：

Aks-create-cluster.sh

```
az aks create \
    --resource-group devResourceGroup \
    --name myCluster \
    --node-count 2 \
    --service-principal <appId> \
    --client-secret <password> \
    --generate-ssh-keys
```

此命令假定存在名为 `devResourceGroup` 的资源组和名为 `devCluster` 的集群。对于 `appId` 和 `password`，请使用服务主体创建步骤中的值。

最后，要在您的计算机上生成正确的 `kubectl` 配置，您可以运行以下命令：

```
az aks get-credentials --resource-group devResourceGroup --name myCluster
```

到这一步，您应该能够正确运行 `kubectl` 命令。使用 `kubectl get nodes` 命令测试配置。

# 程序化集群创建工具

有几种可用的工具可以在各种非托管环境中引导 Kubernetes 集群。我们将重点关注三种最流行的工具：Kubeadm、Kops 和 Kubespray。每种工具都针对不同的用例，并且通常通过不同的方法工作。

## Kubeadm

Kubeadm 是由 Kubernetes 社区创建的工具，旨在简化已经配置好的基础架构上的集群创建。与 Kops 不同，Kubeadm 无法在云服务上提供基础架构。它只是创建一个符合 Kubernetes 一致性测试的最佳实践集群。Kubeadm 对基础架构是不可知的-它应该可以在任何可以运行 Linux VM 的地方工作。

## Kops

Kops 是一种流行的集群配置工具。它为您的集群提供基础架构，安装所有集群组件，并验证您的集群功能。它还可以用于执行各种集群操作，如升级、节点旋转等。Kops 目前支持 AWS，在撰写本书时，还支持 Google Compute Engine 和 OpenStack 的 beta 版本，以及 VMware vSphere 和 DigitalOcean 的 alpha 版本。

## Kubespray

Kubespray 与 Kops 和 Kubeadm 都不同。与 Kops 不同，Kubespray 并不固有地提供集群资源。相反，Kubespray 允许您在 Ansible 和 Vagrant 之间进行选择，以执行配置、编排和节点设置。

与 Kubeadm 相比，Kubespray 集成了更少的集群创建和生命周期流程。Kubespray 的新版本允许您在节点设置后专门使用 Kubeadm 进行集群创建。

重要说明

由于使用 Kubespray 创建集群需要一些特定于 Ansible 的领域知识，我们将不在本书中讨论这个问题-但可以在[`github.com/kubernetes-sigs/kubespray/blob/master/docs/getting-started.md`](https://github.com/kubernetes-sigs/kubespray/blob/master/docs/getting-started.md)找到有关 Kubespray 的所有信息的指南。

# 使用 Kubeadm 创建集群

要使用 Kubeadm 创建集群，您需要提前配置好节点。与任何其他 Kubernetes 集群一样，我们需要运行 Linux 的 VM 或裸金属服务器。

为了本书的目的，我们将展示如何使用单个主节点引导 Kubeadm 集群。对于高可用设置，您需要在其他主节点上运行额外的加入命令，您可以在[`kubernetes.io/docs/setup/production-environment/tools/kubeadm/high-availability/`](https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/high-availability/)找到。

## 安装 Kubeadm

首先，您需要在所有节点上安装 Kubeadm。每个支持的操作系统的安装说明可以在[`kubernetes.io/docs/setup/production-environment/tools/kubeadm/install-kubeadm`](https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/install-kubeadm)找到。

对于每个节点，还要确保所有必需的端口都是开放的，并且已安装您打算使用的容器运行时。

## 启动主节点

要快速启动使用 Kubeadm 的主节点，您只需要运行一个命令：

```
kubeadm init
```

此初始化命令可以接受几个可选参数 - 根据您的首选集群设置、网络等，您可能需要使用它们。

在`init`命令的输出中，您将看到一个`kubeadm join`命令。确保保存此命令。

## 启动工作节点

为了引导工作节点，您需要运行保存的`join`命令。命令的形式如下：

```
kubeadm join --token [TOKEN] [IP ON MASTER]:[PORT ON MASTER] --discovery-token-ca-cert-hash sha256:[HASH VALUE]
```

此命令中的令牌是引导令牌。它用于验证节点之间的身份，并将新节点加入集群。拥有此令牌的访问权限即可加入新节点到集群中，因此请谨慎对待。

## 设置 kubectl

使用 Kubeadm，kubectl 已经在主节点上正确设置。但是，要从任何其他机器或集群外部使用 kubectl，您可以将主节点上的配置复制到本地机器：

```
scp root@[IP OF MASTER]:/etc/kubernetes/admin.conf .
kubectl --kubeconfig ./admin.conf get nodes 
```

这个`kubeconfig`将是集群管理员配置 - 为了指定其他用户（和权限），您需要添加新的服务账户并为他们生成`kubeconfig`文件。

# 使用 Kops 创建集群

由于 Kops 将为您提供基础设施，因此无需预先创建任何节点。您只需要安装 Kops，确保您的云平台凭据有效，并立即创建您的集群。Kops 可以安装在 Linux、macOS 和 Windows 上。

在本教程中，我们将介绍如何在 AWS 上创建一个集群，但您可以在 Kops 文档中找到其他支持的 Kops 平台的说明，网址为[`github.com/kubernetes/kops/tree/master/docs`](https://github.com/kubernetes/kops/tree/master/docs)。

## 在 macOS 上安装

在 OS X 上，安装 Kops 的最简单方法是使用 Homebrew：

```
brew update && brew install kops
```

或者，您可以从 Kops GitHub 页面上获取最新的稳定 Kops 二进制文件，网址为[`github.com/kubernetes/kops/releases/tag/1.12.3`](https://github.com/kubernetes/kops/releases/tag/1.12.3)。

## 在 Linux 上安装

在 Linux 上，您可以通过以下命令安装 Kops：

Kops-linux-install.sh

```
curl -LO https://github.com/kubernetes/kops/releases/download/$(curl -s https://api.github.com/repos/kubernetes/kops/releases/latest | grep tag_name | cut -d '"' -f 4)/kops-linux-amd64
chmod +x kops-linux-amd64
sudo mv kops-linux-amd64 /usr/local/bin/kops
```

## 在 Windows 上安装

要在 Windows 上安装 Kops，您需要从[`github.com/kubernetes/kops/releases/latest`](https://github.com/kubernetes/kops/releases/latest)下载最新的 Windows 版本，将其重命名为`kops.exe`，并将其添加到您的`path`变量中。

## 设置 Kops 的凭据

为了让 Kops 工作，您需要在您的机器上具有一些必需的 IAM 权限的 AWS 凭据。为了安全地执行此操作，您需要为 Kops 专门创建一个 IAM 用户。

首先，为`kops`用户创建一个 IAM 组：

```
aws iam create-group --group-name kops_users
```

然后，为`kops_users`组附加所需的角色。为了正常运行，Kops 将需要`AmazonEC2FullAccess`，`AmazonRoute53FullAccess`，`AmazonS3FullAccess`，`IAMFullAccess`和`AmazonVPCFullAccess`。我们可以通过运行以下命令来实现这一点：

提供-aws-policies-to-kops.sh

```
aws iam attach-group-policy --policy-arn arn:aws:iam::aws:policy/AmazonEC2FullAccess --group-name kops
aws iam attach-group-policy --policy-arn arn:aws:iam::aws:policy/AmazonRoute53FullAccess --group-name kops
aws iam attach-group-policy --policy-arn arn:aws:iam::aws:policy/AmazonS3FullAccess --group-name kops
aws iam attach-group-policy --policy-arn arn:aws:iam::aws:policy/IAMFullAccess --group-name kops
aws iam attach-group-policy --policy-arn arn:aws:iam::aws:policy/AmazonVPCFullAccess --group-name kops
```

最后，创建`kops`用户，将其添加到`kops_users`组，并创建程序访问密钥，然后保存：

```
aws iam create-user --user-name kops
aws iam add-user-to-group --user-name kops --group-name kops_users
aws iam create-access-key --user-name kops
```

为了让 Kops 访问您的新 IAM 凭据，您可以使用以下命令配置 AWS CLI，使用前一个命令（`create-access-key`）中的访问密钥和秘钥：

```
aws configure
export AWS_ACCESS_KEY_ID=$(aws configure get aws_access_key_id)
export AWS_SECRET_ACCESS_KEY=$(aws configure get aws_secret_access_key)
```

## 设置状态存储

凭据设置好后，我们可以开始创建我们的集群。在这种情况下，我们将构建一个简单的基于 gossip 的集群，因此我们不需要处理 DNS。要查看可能的 DNS 设置，您可以查看 Kops 文档（[`github.com/kubernetes/kops/tree/master/docs`](https://github.com/kubernetes/kops/tree/master/docs)）。

首先，我们需要一个位置来存储我们的集群规范。由于我们在 AWS 上，S3 非常适合这个任务。

像往常一样，使用 S3 时，存储桶名称需要是唯一的。您可以使用 AWS SDK 轻松创建一个存储桶（确保将`my-domain-dev-state-store`替换为您想要的 S3 存储桶名称）：

```
aws s3api create-bucket \
    --bucket my-domain-dev-state-store \
    --region us-east-1
```

启用存储桶加密和版本控制是最佳实践：

```
aws s3api put-bucket-versioning --bucket prefix-example-com-state-store  --versioning-configuration Status=Enabled
aws s3api put-bucket-encryption --bucket prefix-example-com-state-store --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'
```

最后，要设置 Kops 的变量，请使用以下命令：

```
export NAME=devcluster.k8s.local
export KOPS_STATE_STORE=s3://my-domain-dev-cluster-state-store
```

重要提示

Kops 支持多种状态存储位置，如 AWS S3，Google Cloud Storage，Kubernetes，DigitalOcean，OpenStack Swift，阿里云和 memfs。但是，您可以将 Kops 状态仅保存到本地文件并使用该文件。云端状态存储的好处是多个基础架构开发人员可以访问并使用版本控制进行更新。

## 创建集群

使用 Kops，我们可以部署任何规模的集群。在本指南的目的是，我们将通过在三个可用区域跨越工作节点和主节点来部署一个生产就绪的集群。我们将使用 US-East-1 地区，主节点和工作节点都将是`t2.medium`实例。

要为此集群创建配置，可以运行以下`kops create`命令：

Kops-create-cluster.sh

```
kops create cluster \
    --node-count 3 \
    --zones us-east-1a,us-east-1b,us-east-1c \
    --master-zones us-east-1a,us-east-1b,us-east-1c \
    --node-size t2.medium \
    --master-size t2.medium \
    ${NAME}
```

要查看已创建的配置，请使用以下命令：

```
kops edit cluster ${NAME}
```

最后，要创建我们的集群，请运行以下命令：

```
kops update cluster ${NAME} --yes
```

集群创建过程可能需要一些时间，但一旦完成，您的`kubeconfig`应该已经正确配置，可以使用 kubectl 与您的新集群进行交互。

# 完全从头开始创建集群

完全从头开始创建一个 Kubernetes 集群是一个多步骤的工作，可能需要跨越本书的多个章节。然而，由于我们的目的是尽快让您开始使用 Kubernetes，我们将避免描述整个过程。

如果您有兴趣从头开始创建集群，无论是出于教育目的还是需要精细定制您的集群，都可以参考*Kubernetes The Hard Way*，这是由*Kelsey Hightower*编写的完整集群创建教程。它可以在[`github.com/kelseyhightower/kubernetes-the-hard-way`](https://github.com/kelseyhightower/kubernetes-the-hard-way)找到。

既然我们已经解决了这个问题，我们可以继续概述手动创建集群的过程。

## 配置您的节点

首先，您需要一些基础设施来运行 Kubernetes。通常，虚拟机是一个很好的选择，尽管 Kubernetes 也可以在裸机上运行。如果您在一个不能轻松添加节点的环境中工作（这会消除云的许多扩展优势，但在企业环境中绝对可行），您需要足够的节点来满足应用程序的需求。这在空隔离环境中更有可能成为一个问题。

一些节点将用于主控制平面，而其他节点将仅用作工作节点。没有必要从内存或 CPU 的角度使主节点和工作节点相同 - 甚至可以有一些较弱的和一些更强大的工作节点。这种模式会导致一个非同质的集群，其中某些节点更适合特定的工作负载。

## 为 TLS 创建 Kubernetes 证书颁发机构

为了正常运行，所有主要控制平面组件都需要 TLS 证书。为了创建这些证书，需要创建一个证书颁发机构（CA），它将进一步创建 TLS 证书。

要创建 CA，需要引导公钥基础设施（PKI）。对于这个任务，可以使用任何 PKI 工具，但 Kubernetes 文档中使用的是 cfssl。

一旦为所有组件创建了 PKI、CA 和 TLS 证书，下一步是为控制平面和工作节点组件创建配置文件。

## 创建配置文件

需要为 kubelet、kube-proxy、kube-controller-manager 和 kube-scheduler 组件创建配置文件。它们将使用这些配置文件中的证书与 kube-apiserver 进行身份验证。

## 创建 etcd 集群并配置加密

通过一个带有数据加密密钥的 YAML 文件来处理数据加密配置。此时，需要启动 etcd 集群。

为此，在每个节点上创建带有 etcd 进程配置的 systemd 文件。然后在每个节点上使用 systemctl 启动 etcd 服务器。

这是一个 etcd 的 systemd 文件示例。其他控制平面组件的 systemd 文件将类似于这个：

示例-systemd-control-plane

```
[Unit]
Description=etcd
Documentation=https://github.com/coreos
[Service]
Type=notify
ExecStart=/usr/local/bin/etcd \\
  --name ${ETCD_NAME} \\
  --cert-file=/etc/etcd/kubernetes.pem \\
  --key-file=/etc/etcd/kubernetes-key.pem \\
  --peer-cert-file=/etc/etcd/kubernetes.pem \\
  --peer-key-file=/etc/etcd/kubernetes-key.pem \\
  --trusted-ca-file=/etc/etcd/ca.pem \\
  --peer-trusted-ca-file=/etc/etcd/ca.pem \\
  --peer-client-cert-auth \\
  --initial-cluster-state new \\
  --data-dir=/var/lib/etcd
Restart=on-failure
RestartSec=5
[Install]
WantedBy=multi-user.target
```

该服务文件为我们的 etcd 组件提供了运行时定义，它将在每个主节点上启动。要在我们的节点上实际启动 etcd，我们运行以下命令：

```
{
  sudo systemctl daemon-reload
  sudo systemctl enable etcd
  sudo systemctl start etcd
}
```

这使得`etcd`服务能够在节点重新启动时自动重新启动。

## 引导控制平面组件

在主节点上引导控制平面组件的过程类似于创建`etcd`集群所使用的过程。为每个组件创建`systemd`文件 - API 服务器、控制器管理器和调度器 - 然后使用`systemctl`命令启动每个组件。

先前创建的配置文件和证书也需要包含在每个主节点上。

让我们来看看我们的`kube-apiserver`组件的服务文件定义，按照以下各节进行拆分。`Unit`部分只是我们`systemd`文件的一个快速描述：

```
[Unit]
Description=Kubernetes API Server
Documentation=https://github.com/kubernetes/kubernetes
```

Api-server-systemd-example

第二部分是服务的实际启动命令，以及要传递给服务的任何变量：

```
[Service]
ExecStart=/usr/local/bin/kube-apiserver \\
  --advertise-address=${INTERNAL_IP} \\
  --allow-privileged=true \\
  --apiserver-count=3 \\
  --audit-log-maxage=30 \\
  --audit-log-maxbackup=3 \\
  --audit-log-maxsize=100 \\
  --audit-log-path=/var/log/audit.log \\
  --authorization-mode=Node,RBAC \\
  --bind-address=0.0.0.0 \\
  --client-ca-file=/var/lib/kubernetes/ca.pem \\
  --enable-admission-plugins=NamespaceLifecycle,NodeRestriction,LimitRanger,ServiceAccount,DefaultStorageClass,ResourceQuota \\
  --etcd-cafile=/var/lib/kubernetes/ca.pem \\
  --etcd-certfile=/var/lib/kubernetes/kubernetes.pem \\
  --etcd-keyfile=/var/lib/kubernetes/kubernetes-key.pem \\
  --etcd-
  --service-account-key-file=/var/lib/kubernetes/service-account.pem \\
  --service-cluster-ip-range=10.10.0.0/24 \\
  --service-node-port-range=30000-32767 \\
  --tls-cert-file=/var/lib/kubernetes/kubernetes.pem \\
  --tls-private-key-file=/var/lib/kubernetes/kubernetes-key.pem \\
  --v=2
```

最后，`Install`部分允许我们指定一个`WantedBy`目标：

```
Restart=on-failure
RestartSec=5
 [Install]
WantedBy=multi-user.target
```

`kube-scheduler`和`kube-controller-manager`的服务文件将与`kube-apiserver`的定义非常相似，一旦我们准备在节点上启动组件，这个过程就很容易：

```
{
  sudo systemctl daemon-reload
  sudo systemctl enable kube-apiserver kube-controller-manager kube-scheduler
  sudo systemctl start kube-apiserver kube-controller-manager kube-scheduler
}
```

与`etcd`类似，我们希望确保服务在节点关闭时重新启动。

## 引导工作节点

工作节点上也是类似的情况。需要创建并使用`systemctl`运行`kubelet`、容器运行时、`cni`和`kube-proxy`的服务规范。`kubelet`配置将指定上述 TLS 证书，以便它可以通过 API 服务器与控制平面通信。

让我们看看我们的`kubelet`服务定义是什么样子的：

Kubelet-systemd-example

```
[Unit]
Description=Kubernetes Kubelet
Documentation=https://github.com/kubernetes/kubernetes
After=containerd.service
Requires=containerd.service
[Service]
ExecStart=/usr/local/bin/kubelet \\
  --config=/var/lib/kubelet/kubelet-config.yaml \\
  --container-runtime=remote \\
  --container-runtime-endpoint=unix:///var/run/containerd/containerd.sock \\
  --image-pull-progress-deadline=2m \\
  --kubeconfig=/var/lib/kubelet/kubeconfig \\
  --network-plugin=cni \\
  --register-node=true \\
  --v=2
Restart=on-failure
RestartSec=5
[Install]
WantedBy=multi-user.target
```

正如你所看到的，这个服务定义引用了`cni`、容器运行时和`kubelet-config`文件。`kubelet-config`文件包含我们工作节点所需的 TLS 信息。

在引导工作节点和主节点之后，集群应该可以通过作为 TLS 设置的一部分创建的管理员`kubeconfig`文件来使用。

# 总结

在本章中，我们回顾了创建 Kubernetes 集群的几种方法。我们研究了使用 minikube 在本地创建最小的集群，设置在 Azure、AWS 和 Google Cloud 上管理的 Kubernetes 服务的集群，使用 Kops 配置工具创建集群，最后，从头开始手动创建集群。

现在我们有了在几种不同环境中创建 Kubernetes 集群的技能，我们可以继续使用 Kubernetes 来运行应用程序。

在下一章中，我们将学习如何在 Kubernetes 上开始运行应用程序。您对 Kubernetes 在架构层面的工作原理的了解应该会让您更容易理解接下来几章中的概念。

# 问题

1.  minikube 有什么作用？

1.  使用托管 Kubernetes 服务有哪些缺点？

1.  Kops 与 Kubeadm 有何不同？主要区别是什么？

1.  Kops 支持哪些平台？

1.  在手动创建集群时，如何指定主要集群组件？它们如何在每个节点上运行？

# 进一步阅读

+   官方 Kubernetes 文档：[`kubernetes.io/docs/home/`](https://kubernetes.io/docs/home/)

+   *Kubernetes The Hard Way*：[`github.com/kelseyhightower/kubernetes-the-hard-way`](https://github.com/kelseyhightower/kubernetes-the-hard-way)


# 第三章：在 Kubernetes 上运行应用程序容器

本章包含了 Kubernetes 提供的最小的乐高积木块——Pod 的全面概述。其中包括 PodSpec YAML 格式和可能的配置的解释，以及 Kubernetes 如何处理和调度 Pod 的简要讨论。Pod 是在 Kubernetes 上运行应用程序的最基本方式，并且在所有高阶应用程序控制器中使用。

在本章中，我们将涵盖以下主题：

+   什么是 Pod？

+   命名空间

+   Pod 的生命周期

+   Pod 资源规范

+   Pod 调度

# 技术要求

为了运行本章详细介绍的命令，您需要一台支持`kubectl`命令行工具的计算机，以及一个可用的 Kubernetes 集群。请参见*第一章*，*与 Kubernetes 通信*，了解快速启动和运行 Kubernetes 的几种方法，以及如何安装`kubectl`工具的说明。

本章中使用的代码可以在书的 GitHub 存储库中找到以下链接：

[`github.com/PacktPublishing/Cloud-Native-with-Kubernetes/tree/master/Chapter3`](https://github.com/PacktPublishing/Cloud-Native-with-Kubernetes/tree/master/Chapter3)

# 什么是 Pod？

Pod 是 Kubernetes 中最简单的计算资源。它指定一个或多个容器由 Kubernetes 调度程序在节点上启动和运行。Pod 有许多潜在的配置和扩展，但仍然是在 Kubernetes 上运行应用程序的最基本方式。

重要说明

单独一个 Pod 并不是在 Kubernetes 上运行应用程序的很好的方式。Pod 应该被视为一次性的东西，以便充分利用像 Kubernetes 这样的容器编排器的真正能力。这意味着将容器（因此也是 Pod）视为牲畜，而不是宠物。为了真正利用容器和 Kubernetes，应用程序应该在自愈、可扩展的组中运行。Pod 是这些组的构建块，我们将在后面的章节中讨论如何以这种方式配置应用程序。

# 实现 Pod

Pod 是使用 Linux 隔离原则（如组和命名空间）实现的，并且通常可以被视为逻辑主机。Pod 运行一个或多个容器（可以基于 Docker、CRI-O 或其他运行时），这些容器可以以与 VM 上的不同进程通信的方式相互通信。

为了使两个不同 Pod 中的容器进行通信，它们需要通过 IP 访问另一个 Pod（和容器）。默认情况下，只有运行在同一个 Pod 上的容器才能使用更低级别的通信方法，尽管可以配置不同的 Pod 以使它们能够通过主机 IPC 相互通信。

## Pod 范例

在最基本的层面上，有两种类型的 Pods：

+   单容器 Pods

+   多容器 Pods

通常最好的做法是每个 Pod 包含一个单独的容器。这种方法允许您分别扩展应用程序的不同部分，并且在创建一个可以启动和运行而不出现问题的 Pod 时通常会保持简单。

另一方面，多容器 Pods 更复杂，但在各种情况下都可能很有用：

+   如果您的应用程序有多个部分运行在不同的容器中，但彼此之间紧密耦合，您可以将它们都运行在同一个 Pod 中，以使通信和文件系统访问无缝。

+   在实施*侧车*模式时，实用程序容器被注入到主应用程序旁边，用于处理日志记录、度量、网络或高级功能，比如服务网格（更多信息请参阅*第十四章*，*服务网格和无服务器*）。

下图显示了一个常见的侧车实现：

![图 3.1 - 常见的侧边栏实现](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cld-ntv-k8s/img/B14790_03_001.jpg)

图 3.1 - 常见的侧边栏实现

在这个例子中，我们有一个只有两个容器的 Pod：我们的应用容器运行一个 Web 服务器，一个日志应用程序从我们的服务器 Pod 中拉取日志并将其转发到我们的日志基础设施。这是侧车模式非常适用的一个例子，尽管许多日志收集器在节点级别工作，而不是在 Pod 级别，所以这并不是在 Kubernetes 中从我们的应用容器收集日志的通用方式。

## Pod 网络

正如我们刚才提到的，Pods 有自己的 IP 地址，可以用于 Pod 间通信。每个 Pod 都有一个 IP 地址和端口，如果有多个容器运行在一个 Pod 中，这些端口是共享的。

在 Pod 内部，正如我们之前提到的，容器可以在不调用封装 Pod 的 IP 的情况下进行通信 - 相反，它们可以简单地使用 localhost。这是因为 Pod 内的容器共享网络命名空间 - 本质上，它们通过相同的*bridge*进行通信，这是使用虚拟网络接口实现的。

## Pod 存储

Kubernetes 中的存储是一个独立的大主题，我们将在*第七章*中深入讨论它 - 但现在，您可以将 Pod 存储视为附加到 Pod 的持久或非持久卷。非持久卷可以被 Pod 用于存储数据或文件，具体取决于类型，但它们在 Pod 关闭时会被删除。持久类型的卷将在 Pod 关闭后保留，并且甚至可以用于在多个 Pod 或应用程序之间共享数据。

在我们继续讨论 Pod 之前，我们将花一点时间讨论命名空间。由于我们在处理 Pod 时将使用`kubectl`命令，了解命名空间如何与 Kubernetes 和`kubectl`相关联非常重要，因为这可能是一个重要的“坑”。

## 命名空间

在*第一章*的*与 Kubernetes 通信*部分，我们简要讨论了命名空间，但在这里我们将重申并扩展它们的目的。命名空间是一种在集群中逻辑上分隔不同区域的方式。一个常见的用例是每个环境一个命名空间 - 一个用于开发，一个用于暂存，一个用于生产 - 所有这些都存在于同一个集群中。

正如我们在*授权*部分中提到的，可以按命名空间指定用户权限 - 例如，允许用户向`dev`命名空间部署新应用程序和资源，但不允许向生产环境部署。

在运行的集群中，您可以通过运行`kubectl get namespaces`或`kubectl get ns`来查看存在哪些命名空间，这应该会产生以下输出：

```
NAME          STATUS    AGE
default       Active    1d
kube-system   Active    1d
kube-public   Active    1d
```

通过以下命令可以创建一个命名空间：`kubectl create namespace staging`，或者使用以下 YAML 资源规范运行`kubectl apply -f /path/to/file.yaml`：

Staging-ns.yaml

```
apiVersion: v1
kind: Namespace
metadata:
  name: staging
```

如您所见，`Namespace`规范非常简单。让我们继续讨论更复杂的内容 - PodSpec 本身。

## Pod 生命周期

要快速查看集群中正在运行的 Pods，您可以运行`kubectl get pods`或`kubectl get pods --all-namespaces`来分别获取当前命名空间中的 Pods（由您的`kubectl`上下文定义，如果未指定，则为默认命名空间）或所有命名空间中的 Pods。

`kubectl get pods`的输出如下：

```
NAME     READY   STATUS    RESTARTS   AGE
my-pod   1/1     Running   0          9s
```

正如您所看到的，Pod 具有一个`STATUS`值，告诉我们 Pod 当前处于哪种状态。

Pod 状态的值如下：

+   **运行**：在`运行`状态下，Pod 已成功启动其容器，没有任何问题。如果 Pod 只有一个容器，并且处于`运行`状态，那么容器尚未完成或退出其进程。它也可能正在重新启动，您可以通过检查`READY`列来判断。例如，如果`READY`值为`0/1`，这意味着 Pod 中的容器当前未通过健康检查。这可能是由于各种原因：容器可能仍在启动，数据库连接可能无法正常工作，或者一些重要配置可能会阻止应用程序进程启动。

+   **成功**：如果您的 Pod 容器设置为运行可以完成或退出的命令（不是长时间运行的命令，例如启动 Web 服务器），则如果这些容器已完成其进程命令，Pod 将显示`成功`状态。

+   **挂起**：`挂起`状态表示 Pod 中至少有一个容器正在等待其镜像。这可能是因为容器镜像仍在从外部存储库获取，或者因为 Pod 本身正在等待被`kube-scheduler`调度。

+   未知：`未知`状态表示 Kubernetes 无法确定 Pod 实际处于什么状态。这通常意味着 Pod 所在的节点遇到某种错误。可能是磁盘空间不足，与集群的其余部分断开连接，或者遇到其他问题。

+   **失败**：在`失败`状态下，Pod 中的一个或多个容器以失败状态终止。此外，Pod 中的其他容器必须以成功或失败的方式终止。这可能是由于集群删除 Pods 或容器应用程序内部的某些东西破坏了进程而发生的各种原因。

## 理解 Pod 资源规范

由于 Pod 资源规范是我们真正深入研究的第一个资源规范，我们将花时间详细介绍 YAML 文件的各个部分以及它们如何配合。

让我们从一个完全规范的 Pod 文件开始，然后我们可以分解和审查它：

Simple-pod.yaml

```
apiVersion: v1
kind: Pod
metadata:
  name: myApp
  namespace: dev
  labels:
    environment: dev
  annotations:
    customid1: 998123hjhsad 
spec:
  containers:
  - name: my-app-container
    image: busybox
```

这个 Pod YAML 文件比我们在第一章中看到的要复杂一些。它公开了一些新的 Pod 功能，我们将很快进行审查。

### API 版本

让我们从第 1 行开始：`apiVersion`。正如我们在*第一章*中提到的，*与 Kubernetes 通信*，`apiVersion` 告诉 Kubernetes 在创建和配置资源时应查看哪个 API 版本。Pod 在 Kubernetes 中已经存在很长时间，因此 PodSpec 已经固定为 API 版本`v1`。其他资源类型可能除了版本名称外还包含组名 - 例如，在 Kubernetes 中，CronJob 资源使用`batch/v1beta1` `apiVersion`，而 Job 资源使用`batch/v1` `apiVersion`。在这两种情况下，`batch` 对应于 API 组名。

### Kind

`kind` 值对应于 Kubernetes 中资源类型的实际名称。在这种情况下，我们正在尝试规范一个 Pod，所以这就是我们放置的内容。`kind` 值始终采用驼峰命名法，例如 `Pod`、`ConfigMap`、`CronJob` 等。

重要说明

要获取完整的`kind`值列表，请查看官方 Kubernetes 文档[`kubernetes.io/docs/home/`](https://kubernetes.io/docs/home/)。新的 Kubernetes `kind` 值会在新版本中添加，因此本书中审查的内容可能不是详尽的列表。

### 元数据

元数据是一个顶级键，可以在其下具有几个不同的值。首先，`name` 是资源名称，这是资源通过`kubectl`显示的名称，也是在`etcd`中存储的名称。`namespace` 对应于资源应该被创建在的命名空间。如果在 YAML 规范中未指定命名空间，则资源将被创建在`default`命名空间中 - 除非在`apply`或`create`命令中指定了命名空间。

接下来，`labels` 是用于向资源添加元数据的键值对。`labels` 与其他元数据相比是特殊的，因为它们默认用于 Kubernetes 本机`selectors`中，以过滤和选择资源 - 但它们也可以用于自定义功能。

最后，`metadata`块可以承载多个`annotations`，就像`labels`一样，可以被控制器和自定义 Kubernetes 功能用来提供额外的配置和特定功能的数据。在这个 PodSpec 中，我们在元数据中指定了几个注释：

pod-with-annotations.yaml

```
apiVersion: v1
kind: Pod
metadata:
  name: myApp
  namespace: dev
  labels:
    environment: dev
  annotations:
    customid1: 998123hjhsad
    customid2: 1239808908sd 
spec:
  containers:
  - name: my-app-container
    image: busybox
```

通常，最好使用`labels`来进行 Kubernetes 特定功能和选择器的配置，同时使用`annotations`来添加数据或扩展功能 - 这只是一种惯例。

### 规范

`spec`是包含特定于资源的配置的顶级键。在这种情况下，由于我们的`kind`值是`Pod`，我们将添加一些特定于我们的 Pod 的配置。所有进一步的键将缩进在这个`spec`键下，并将代表我们的 Pod 配置。

### 容器

`containers`键期望一个或多个容器的列表，这些容器将在一个 Pod 中运行。每个容器规范将公开其自己的配置值，这些配置值缩进在资源 YAML 中的容器列表项下。我们将在这里审查一些这些配置，但是要获取完整列表，请查看 Kubernetes 文档（[`kubernetes.io/docs/home/`](https://kubernetes.io/docs/home/)）。

### 名称

在容器规范中，`name`指的是容器在 Pod 中的名称。容器名称可以用于使用`kubectl logs`命令特别访问特定容器的日志，但这部分我们以后再说。现在，请确保为 Pod 中的每个容器选择一个清晰的名称，以便在调试时更容易处理事情。

### 图像

对于每个容器，`image`用于指定应在 Pod 中启动的 Docker（或其他运行时）镜像的名称。默认情况下，图像将从配置的存储库中拉取，这是公共 Docker Hub，但也可以是私有存储库。

就是这样 - 这就是你需要指定一个 Pod 并在 Kubernetes 中运行它的全部内容。从`Pod`部分开始的一切都属于*额外配置*的范畴。

### Pod 资源规范

Pod 可以配置为具有分配给它们的特定内存和计算量。这可以防止特别耗费资源的应用程序影响集群性能，也可以帮助防止内存泄漏。可以指定两种可能的资源 - `cpu`和`memory`。对于每个资源，有两种不同类型的规范，`Requests`和`Limits`，总共有四个可能的资源规范键。

内存请求和限制可以使用任何典型的内存数字后缀进行配置，或者其二的幂等价 - 例如，50 Mi（mebibytes），50 MB（megabytes）或 1 Gi（gibibytes）。

CPU 请求和限制可以通过使用`m`来配置，它对应于 1 毫 CPU，或者只是使用一个小数。因此，`200m`等同于`0.2`，相当于 20%或五分之一的逻辑 CPU。无论核心数量如何，这个数量都将是相同的计算能力。1 CPU 等于 AWS 中的虚拟核心或 GCP 中的核心。让我们看看这些资源请求和限制在我们的 YAML 文件中是什么样子的：

pod-with-resource-limits.yaml

```
apiVersion: v1
kind: Pod
metadata:
  name: myApp
spec:
  containers:
  - name: my-app-container
    image: mydockername
    resources:
      requests:
        memory: "50Mi"
        cpu: "100m"
      limits:
        memory: "200Mi"
        cpu: "500m"
```

在这个`Pod`中，我们有一个运行 Docker 镜像的容器，该容器在`cpu`和`memory`上都指定了请求和限制。在这种情况下，我们的容器镜像名称`mydockername`是一个占位符 - 但是如果您想在此示例中测试 Pod 资源限制，可以使用 busybox 镜像。

### 容器启动命令

当容器在 Kubernetes Pod 中启动时，它将运行容器的默认启动脚本 - 例如，在 Docker 容器规范中指定的脚本。为了使用不同的命令或附加参数覆盖此功能，您可以提供`command`和`args`键。让我们看一个配置了`start`命令和一些参数的容器：

pod-with-start-command.yaml

```
apiVersion: v1
kind: Pod
metadata:
  name: myApp
spec:
  containers:
  - name: my-app-container
    image: mydockername
    command: ["run"]
    args: ["--flag", "T", "--run-type", "static"]
```

正如您所看到的，我们指定了一个命令以及作为字符串数组的参数列表，用逗号分隔空格。

### 初始化容器

`init`容器是 Pod 中特殊的容器，在正常 Pod 容器启动之前启动、运行和关闭。

`init`容器可用于许多不同的用例，例如在应用程序启动之前初始化文件，或者确保其他应用程序或服务在启动 Pod 之前正在运行。

如果指定了多个`init`容器，它们将按顺序运行，直到所有`init`容器都关闭。因此，`init`容器必须运行一个完成并具有端点的脚本。如果您的`init`容器脚本或应用程序继续运行，Pod 中的正常容器将不会启动。

在下面的 Pod 中，`init`容器正在运行一个循环，通过`nslookup`检查我们的`config-service`是否存在。一旦它看到`config-service`已经启动，脚本就会结束，从而触发我们的`my-app`应用容器启动：

pod-with-init-container.yaml

```
apiVersion: v1
kind: Pod
metadata:
  name: myApp
spec:
  containers:
  - name: my-app
    image: mydockername
    command: ["run"]
  initContainers:
  - name: init-before
    image: busybox
    command: ['sh', '-c', 'until nslookup config-service; do echo config-service not up; sleep 2; done;']
```

重要提示

当`init`容器失败时，Kubernetes 将自动重新启动 Pod，类似于通常的 Pod 启动功能。可以通过在 Pod 级别更改`restartPolicy`来更改此功能。

这是一个显示 Kubernetes 中典型 Pod 启动流程的图表：

![图 3.2-初始化容器流程图](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cld-ntv-k8s/img/B14790_03_002.jpg)

图 3.2-初始化容器流程图

如果一个 Pod 有多个`initContainer`，它们将按顺序被调用。这对于那些设置了必须按顺序执行的模块化步骤的`initContainers`非常有价值。以下 YAML 显示了这一点：

pod-with-multiple-init-containers.yaml

```
apiVersion: v1
kind: Pod
metadata:
  name: myApp
spec:
  containers:
  - name: my-app
    image: mydockername
    command: ["run"]
  initContainers:
  - name: init-step-1
    image: step1-image
    command: ['start-command']
  - name: init-step-2
    image: step2-image
    command: ['start-command']
```

例如，在这个`Pod` YAML 文件中，`step-1 init`容器需要在调用`init-step-2`之前成功，两者都需要在启动`my-app`容器之前显示成功。

### 在 Kubernetes 中引入不同类型的探针

为了知道容器（因此也是 Pod）何时失败，Kubernetes 需要知道如何测试容器是否正常工作。我们通过定义`probes`来实现这一点，Kubernetes 可以在指定的间隔运行这些`probes`，以确定容器是否正常工作。

Kubernetes 允许我们配置三种类型的探针-就绪、存活和启动。

### 就绪探针

首先，就绪探针可用于确定容器是否准备好执行诸如通过 HTTP 接受流量之类的功能。这些探针在应用程序运行的初始阶段非常有帮助，例如，当应用程序可能仍在获取配置，尚未准备好接受连接时。

让我们看一下配置了就绪探针的 Pod 是什么样子。接下来是一个附有就绪探针的 PodSpec：

pod-with-readiness-probe.yaml

```
apiVersion: v1
kind: Pod
metadata:
  name: myApp
spec:
  containers:
  - name: my-app
    image: mydockername
    command: ["run"]
    ports:
    - containerPort: 8080
    readinessProbe:
      exec:
        command:
        - cat
        - /tmp/thisfileshouldexist.txt
      initialDelaySeconds: 5
      periodSeconds: 5
```

首先，正如您所看到的，探针是针对每个容器而不是每个 Pod 定义的。Kubernetes 将对每个容器运行所有探针，并使用它来确定 Pod 的总体健康状况。

### 存活探针

存活探针可用于确定应用程序是否因某种原因（例如，由于内存错误）而失败。对于长时间运行的应用程序容器，存活探针可以作为一种方法，帮助 Kubernetes 回收旧的和损坏的 Pod，以便创建新的 Pod。虽然探针本身不会导致容器重新启动，但其他 Kubernetes 资源和控制器将检查探针状态，并在必要时使用它来重新启动 Pod。以下是附有存活探针定义的 PodSpec：

pod-with-liveness-probe.yaml

```
apiVersion: v1
kind: Pod
metadata:
  name: myApp
spec:
  containers:
  - name: my-app
    image: mydockername
    command: ["run"]
    ports:
    - containerPort: 8080
    livenessProbe:
      exec:
        command:
        - cat
        - /tmp/thisfileshouldexist.txt
      initialDelaySeconds: 5
      failureThreshold: 3
      periodSeconds: 5
```

正如您所看到的，我们的活跃性探针与就绪性探针以相同的方式指定，只是增加了`failureThreshold`。

`failureThreshold`值将决定 Kubernetes 在采取行动之前尝试探测的次数。对于活跃性探针，一旦超过`failureThreshold`，Kubernetes 将重新启动 Pod。对于就绪性探针，Kubernetes 将简单地标记 Pod 为`Not Ready`。此阈值的默认值为`3`，但可以更改为大于或等于`1`的任何值。

在这种情况下，我们使用了`exec`机制进行探测。我们将很快审查可用的各种探测机制。

### 启动探针

最后，启动探针是一种特殊类型的探针，它只会在容器启动时运行一次。一些（通常是较旧的）应用程序在容器中启动需要很长时间，因此在容器第一次启动时提供一些额外的余地，可以防止活跃性或就绪性探针失败并导致重新启动。以下是配置了启动探针的 Pod 示例：

pod-with-startup-probe.yaml

```
apiVersion: v1
kind: Pod
metadata:
  name: myApp
spec:
  containers:
  - name: my-app
    image: mydockername
    command: ["run"]
    ports:
    - containerPort: 8080
    startupProbe:
      exec:
        command:
        - cat
        - /tmp/thisfileshouldexist.txt
      initialDelaySeconds: 5
      successThreshold: 2
      periodSeconds: 5
```

启动探针提供的好处不仅仅是延长活跃性或就绪性探针之间的时间 - 它们允许 Kubernetes 在启动后处理问题时保持快速反应，并且（更重要的是）防止启动缓慢的应用程序不断重新启动。如果您的应用程序需要多秒甚至一两分钟才能启动，您将更容易实现启动探针。

`successThreshold`就像它的名字一样，是`failureThreshold`的对立面。它指定在容器标记为`Ready`之前需要连续多少次成功。对于在启动时可能会上下波动然后稳定下来的应用程序（如一些自我集群应用程序），更改此值可能很有用。默认值为`1`，对于活跃性探针，唯一可能的值是`1`，但我们可以更改就绪性和启动探针的值。

### 探测机制配置

有多种机制可以指定这三种探针中的任何一种：`exec`、`httpGet`和`tcpSocket`。

`exec`方法允许您指定在容器内运行的命令。成功执行的命令将导致探测通过，而失败的命令将导致探测失败。到目前为止，我们配置的所有探针都使用了`exec`方法，因此配置应该是不言自明的。如果所选命令（以逗号分隔的列表形式指定的任何参数）失败，探测将失败。

`httpGet`方法允许您为探针指定容器上的 URL，该 URL 将受到 HTTP `GET`请求的访问。如果 HTTP 请求返回的代码在`200`到`400`之间，它将导致探测成功。任何其他 HTTP 代码将导致失败。

`httpGet`的配置如下：

pod-with-get-probe.yaml

```
apiVersion: v1
kind: Pod
metadata:
  name: myApp
spec:
  containers:
  - name: my-app
    image: mydockername
    command: ["run"]
    ports:
    - containerPort: 8080
    livenessProbe:
      httpGet:
        path: /healthcheck
        port: 8001
        httpHeaders:
        - name: My-Header
          value: My-Header-Value
        initialDelaySeconds: 3
        periodSeconds: 3
```

最后，`tcpSocket`方法将尝试在容器上打开指定的套接字，并使用结果来决定成功或失败。`tcpSocket`配置如下：

pod-with-tcp-probe.yaml

```
apiVersion: v1
kind: Pod
metadata:
  name: myApp
spec:
  containers:
  - name: my-app
    image: mydockername
    command: ["run"]
    ports:
    - containerPort: 8080
    readinessProbe:
      tcpSocket:
        port: 8080
      initialDelaySeconds: 5
      periodSeconds: 10
```

正如您所看到的，这种类型的探针接收一个端口，每次检查发生时都会对其进行 ping 测试。

### 常见的 Pod 转换

Kubernetes 中的失败 Pod 往往在不同状态之间转换。对于初次使用者来说，这可能会令人生畏，因此将我们之前列出的 Pod 状态与探针功能相互作用进行分解是很有价值的。再次强调一下，这是我们的状态：

+   `Running`

+   `Succeeded`

+   `Pending`

+   `Unknown`

+   `Failed`

一个常见的流程是运行`kubectl get pods -w`（`-w`标志会在命令中添加一个监视器），然后查看有问题的 Pod 在`Pending`和`Failed`之间的转换。通常情况下，发生的是 Pod（及其容器）正在启动和拉取镜像 - 这是`Pending`状态，因为健康检查尚未开始。

一旦初始探测超时（正如我们在前一节中看到的那样，这是可配置的），第一个探测失败。这可能会持续几秒甚至几分钟，具体取决于失败阈值的高低，状态仍然固定在`Pending`。

最后，我们的失败阈值达到，我们的 Pod 状态转换为`Failed`。在这一点上，有两种情况可能发生，决定纯粹基于 PodSpec 上的`RestartPolicy`，它可以是`Always`、`Never`或`OnFailure`。如果一个 Pod 失败并且`restartPolicy`是`Never`，那么 Pod 将保持在失败状态。如果是其他两个选项之一，Pod 将自动重新启动，并返回到`Pending`，这是我们永无止境的转换循环的根本原因。

举个不同的例子，您可能会看到 Pod 永远停留在`Pending`状态。这可能是由于 Pod 无法被调度到任何节点。这可能是由于资源请求约束（我们将在本书的后面深入讨论，*第八章*，*Pod 放置控件*），或其他问题，比如节点无法访问。

最后，对于`Unknown`，通常 Pod 被调度的节点由于某种原因无法访问 - 例如，节点可能已关闭，或者通过网络无法访问。

### Pod 调度

Pod 调度的复杂性以及 Kubernetes 让您影响和控制它的方式将保存在我们的*第八章*中，*Pod 放置控件* - 但现在我们将回顾基础知识。

在决定在哪里调度一个 Pod 时，Kubernetes 考虑了许多因素，但最重要的是考虑（当不深入研究 Kubernetes 让我们使用的更复杂的控件时）Pod 优先级、节点可用性和资源可用性。

Kubernetes 调度程序操作一个不断的控制循环，监视集群中未绑定（未调度）的 Pod。如果找到一个或多个未绑定的 Pod，调度程序将使用 Pod 优先级来决定首先调度哪一个。

一旦调度程序决定要调度一个 Pod，它将执行几轮和类型的检查，以找到调度 Pod 的节点的局部最优解。后面的检查由细粒度的调度控件决定，我们将在*第八章*中详细介绍*Pod 放置控件*。现在我们只关心前几轮的检查。

首先，Kubernetes 检查当前时刻哪些节点可以被调度。节点可能无法正常工作，或者遇到其他问题，这将阻止新的 Pod 被调度。

其次，Kubernetes 通过检查哪些节点与 PodSpec 中规定的最小资源需求匹配来过滤可调度的节点。

在没有其他放置控制的情况下，调度器将做出决定并将新的 Pod 分配给一个节点。当该节点上的 `kubelet` 看到有一个新的 Pod 分配给它时，该 Pod 将被启动。

# 摘要

在本章中，我们了解到 Pod 是我们在 Kubernetes 中使用的最基本的构建块。对 Pod 及其所有微妙之处有深入的理解非常重要，因为在 Kubernetes 上的所有计算都使用 Pod 作为构建块。现在可能很明显了，但 Pod 是非常小的、独立的东西，不太牢固。在 Kubernetes 上以单个 Pod 运行应用程序而没有控制器是一个糟糕的决定，你的 Pod 出现任何问题都会导致停机时间。

在下一章中，我们将看到如何通过使用 Pod 控制器同时运行应用程序的多个副本来防止这种情况发生。

# 问题

1.  你如何使用命名空间来分隔应用程序环境？

1.  Pod 状态被列为 `Unknown` 的可能原因是什么？

1.  限制 Pod 内存资源的原因是什么？

1.  如果在 Kubernetes 上运行的应用程序经常在失败的探测重新启动 Pod 之前无法及时启动，你应该调整哪种探测类型？就绪性、存活性还是启动？

# 进一步阅读

+   官方 Kubernetes 文档：[`kubernetes.io/docs/home/`](https://kubernetes.io/docs/home/)

+   《Kubernetes The Hard Way》：[`github.com/kelseyhightower/kubernetes-the-hard-way`](https://github.com/kelseyhightower/kubernetes-the-hard-way)


# 第二部分：在 Kubernetes 上配置和部署应用程序

在本节中，您将学习如何在 Kubernetes 上配置和部署应用程序，以及配置存储并将应用程序暴露到集群外部。

本书的这一部分包括以下章节：

+   第四章，扩展和部署您的应用程序

+   第五章，服务和入口 - 与外部世界通信

+   第六章，Kubernetes 应用程序配置

+   第七章，Kubernetes 上的存储

+   第八章，Pod 放置控制


# 第四章：扩展和部署您的应用程序

在本章中，我们将学习用于运行应用程序和控制 Pod 的高级 Kubernetes 资源。首先，我们将介绍 Pod 的缺点，然后转向最简单的 Pod 控制器 ReplicaSets。然后我们将转向部署，这是将应用程序部署到 Kubernetes 的最流行方法。然后，我们将介绍特殊资源，以帮助您部署特定类型的应用程序–水平 Pod 自动缩放器、DaemonSets、StatefulSets 和 Jobs。最后，我们将通过一个完整的示例将所有内容整合起来，演示如何在 Kubernetes 上运行复杂的应用程序。

在本章中，我们将涵盖以下主题：

+   了解 Pod 的缺点及其解决方案

+   使用 ReplicaSets

+   控制部署

+   利用水平 Pod 自动缩放

+   实施 DaemonSets

+   审查 StatefulSets 和 Jobs

+   把所有东西放在一起

# 技术要求

为了运行本章中详细介绍的命令，您需要一台支持`kubectl`命令行工具的计算机，以及一个可用的 Kubernetes 集群。请参阅*第一章*，*与 Kubernetes 通信*，了解快速启动和运行 Kubernetes 的几种方法，以及如何安装`kubectl`工具的说明。

本章中使用的代码可以在书籍的 GitHub 存储库中找到[`github.com/PacktPublishing/Cloud-Native-with-Kubernetes/tree/master/Chapter4`](https://github.com/PacktPublishing/Cloud-Native-with-Kubernetes/tree/master/Chapter4)。

# 了解 Pod 的缺点及其解决方案

正如我们在上一章*第三章*中所回顾的，*在 Kubernetes 上运行应用程序容器*，在 Kubernetes 中，Pod 是在节点上运行一个或多个应用程序容器的实例。创建一个 Pod 就足以像在任何其他容器中一样运行应用程序。

也就是说，使用单个 Pod 来运行应用程序忽略了在容器中运行应用程序的许多好处。容器允许我们将应用程序的每个实例视为一个可以根据需求进行扩展或缩减的无状态项目，通过启动应用程序的新实例来满足需求。

这既可以让我们轻松扩展应用程序，又可以通过在给定时间提供多个应用程序实例来提高应用程序的可用性。如果我们的一个实例崩溃，应用程序仍将继续运行，并将自动扩展到崩溃前的水平。在 Kubernetes 上，我们通过使用 Pod 控制器资源来实现这一点。

## Pod 控制器

Kubernetes 提供了几种 Pod 控制器的选择。最简单的选择是使用 ReplicaSet，它维护特定 Pod 的给定数量的实例。如果一个实例失败，ReplicaSet 将启动一个新实例来替换它。

其次，有部署，它们自己控制一个 ReplicaSet。在 Kubernetes 上运行应用程序时，部署是最受欢迎的控制器，它们使得通过 ReplicaSet 进行滚动更新来升级应用程序变得容易。

水平 Pod 自动缩放器将部署带到下一个级别，允许应用根据性能指标自动缩放到不同数量的实例。

最后，在某些特定情况下可能有一些特殊的控制器可能是有价值的：

+   DaemonSets，每个节点上运行一个应用程序实例并维护它们

+   StatefulSets，其中 Pod 身份保持静态以帮助运行有状态的工作负载

+   作业，它在指定数量的 Pod 上启动，运行完成，然后关闭。

控制器的实际行为，无论是默认的 Kubernetes 控制器，如 ReplicaSet，还是自定义控制器（例如 PostgreSQL Operator），都应该很容易预测。标准控制循环的简化视图看起来像下面的图表：

![图 4.1- Kubernetes 控制器的基本控制循环](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cld-ntv-k8s/img/B14790_04_001.jpg)

图 4.1- Kubernetes 控制器的基本控制循环

正如您所看到的，控制器不断地检查**预期的集群状态**（我们希望有七个此应用程序的 Pod）与**当前的集群状态**（我们有五个此应用程序的 Pod 正在运行）是否匹配。当预期状态与当前状态不匹配时，控制器将通过 API 采取行动来纠正当前状态以匹配预期状态。

到目前为止，您应该明白为什么在 Kubernetes 上需要控制器：Pod 本身在提供高可用性应用程序方面不够强大。让我们继续讨论最简单的控制器：ReplicaSet。

# 使用 ReplicaSets

ReplicaSet 是最简单的 Kubernetes Pod 控制器资源。它取代了较旧的 ReplicationController 资源。

ReplicaSet 和 ReplicationController 之间的主要区别在于 ReplicationController 使用更基本类型的*选择器* - 确定应该受控制的 Pod 的过滤器。

虽然 ReplicationControllers 使用简单的基于等式（*key=value*）的选择器，但 ReplicaSets 使用具有多种可能格式的选择器，例如`matchLabels`和`matchExpressions`，这将在本章中进行审查。

重要说明

除非您有一个非常好的理由，否则不应该使用 ReplicationController 而应该使用 ReplicaSet-坚持使用 ReplicaSets。

ReplicaSets 允许我们通知 Kubernetes 维护特定 Pod 规范的一定数量的 Pod。ReplicaSet 的 YAML 与 Pod 的 YAML 非常相似。实际上，整个 Pod 规范都嵌套在 ReplicaSet 的 YAML 中，位于`template`键下。

还有一些其他关键区别，可以在以下代码块中观察到：

replica-set.yaml

```
apiVersion: apps/v1
kind: ReplicaSet
metadata:
  name: myapp-group
  labels:
    app: myapp
spec:
  replicas: 3
  selector:
    matchLabels:
      app: myapp
  template:
    metadata:
      labels:
        app: myapp
    spec:
      containers:
      - name: myapp-container
        image: busybox
```

正如您所看到的，除了`template`部分（本质上是一个 Pod 定义），在我们的 ReplicaSet 规范中还有一个`selector`键和一个`replicas`键。让我们从`replicas`开始。

## 副本

`replicas`键指定了副本数量，我们的 ReplicaSet 将确保在任何给定时间始终运行指定数量的副本。如果一个 Pod 死掉或停止工作，我们的 ReplicaSet 将创建一个新的 Pod 来替代它。这使得 ReplicaSet 成为一个自愈资源。

ReplicaSet 控制器如何决定一个 Pod 何时停止工作？它查看 Pod 的状态。如果 Pod 的当前状态不是“*Running*”或“*ContainerCreating*”，ReplicaSet 将尝试启动一个新的 Pod。

正如我们在*第三章*中讨论的那样，*在 Kubernetes 上运行应用容器*，容器创建后 Pod 的状态由存活探针、就绪探针和启动探针驱动，这些探针可以针对 Pod 进行特定配置。这意味着您可以设置特定于应用程序的方式来判断 Pod 是否以某种方式损坏，并且您的 ReplicaSet 可以介入并启动一个新的 Pod 来替代它。

## 选择器

`selector`键很重要，因为 ReplicaSet 的工作方式是以选择器为核心实现的控制器。ReplicaSet 的工作是确保与其选择器匹配的运行中的 Pod 数量是正确的。

比如说，你有一个现有的 Pod 运行你的应用程序 `MyApp`。这个 Pod 被标记为 `selector` 键为 `App=MyApp`。

现在假设你想创建一个具有相同应用程序的 ReplicaSet，这将增加你的应用程序的三个额外实例。你使用相同的选择器创建一个 ReplicaSet，并指定三个副本，目的是总共运行四个实例，因为你已经有一个在运行。

一旦你启动 ReplicaSet，会发生什么？你会发现运行该应用程序的总 pod 数将是三个，而不是四个。这是因为 ReplicaSet 有能力接管孤立的 pods 并将它们纳入其管理范围。

当 ReplicaSet 启动时，它会看到已经存在一个与其 `selector` 键匹配的现有 Pod。根据所需的副本数，ReplicaSet 将关闭现有的 Pods 或启动新的 Pods，以匹配 `selector` 以创建正确的数量。

## 模板

`template` 部分包含 Pod，并支持与 Pod YAML 相同的所有字段，包括元数据部分和规范本身。大多数其他控制器都遵循这种模式 - 它们允许你在更大的控制器 YAML 中定义 Pod 规范。

现在你应该了解 ReplicaSet 规范的各个部分以及它们的作用。让我们继续使用我们的 ReplicaSet 来运行应用程序。

## 测试 ReplicaSet

现在，让我们部署我们的 ReplicaSet。

复制先前列出的 `replica-set.yaml` 文件，并在与你的 YAML 文件相同的文件夹中使用以下命令在你的集群上运行它：

```
kubectl apply -f replica-set.yaml
```

为了检查 ReplicaSet 是否已正确创建，请运行 `kubectl get pods` 来获取默认命名空间中的 Pods。

由于我们没有为 ReplicaSet 指定命名空间，它将默认创建。`kubectl get pods` 命令应该给你以下结果：

```
NAME                            READY     STATUS    RESTARTS   AGE
myapp-group-192941298-k705b     1/1       Running   0          1m
myapp-group-192941298-o9sh8     1/1       Running   0        1m
myapp-group-192941298-n8gh2     1/1       Running   0        1m
```

现在，尝试使用以下命令删除一个 ReplicaSet Pod：

```
kubectl delete pod myapp-group-192941298-k705b
```

ReplicaSet 将始终尝试保持指定数量的副本在线。

让我们使用 `kubectl get` 命令再次查看我们正在运行的 pods：

```
NAME                         READY  STATUS             RESTARTS AGE
myapp-group-192941298-u42s0  1/1    ContainerCreating  0     1m
myapp-group-192941298-o9sh8  1/1    Running            0     2m
myapp-group-192941298-n8gh2  1/1    Running            0     2m
```

如你所见，我们的 ReplicaSet 控制器正在启动一个新的 pod，以保持我们的副本数为三。

最后，让我们使用以下命令删除我们的 ReplicaSet：

```
kubectl delete replicaset myapp-group
```

清理了一下我们的集群，让我们继续学习一个更复杂的控制器 - 部署。

# 控制部署

虽然 ReplicaSets 包含了您想要运行高可用性应用程序的大部分功能，但大多数时候您会想要使用部署来在 Kubernetes 上运行应用程序。

部署比 ReplicaSets 有一些优势，实际上它们通过拥有和控制一个 ReplicaSet 来工作。

部署的主要优势在于它允许您指定`rollout`过程 - 也就是说，应用程序升级如何部署到部署中的各个 Pod。这让您可以轻松配置控件以阻止糟糕的升级。

在我们回顾如何做到这一点之前，让我们看一下部署的整个规范：

deployment.yaml

```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp-deployment
  labels:
    app: myapp
spec:
  replicas: 3
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 25%
      maxUnavailable: 25% 
  selector:
    matchLabels:
      app: myapp
  template:
    metadata:
      labels:
        app: myapp
    spec:
      containers:
      - name: myapp-container
        image: busybox
```

正如您所看到的，这与 ReplicaSet 的规范非常相似。我们在这里看到的区别是规范中的一个新键：`strategy`。

使用`strategy`设置，我们可以告诉部署方式升级我们的应用程序，可以通过`RollingUpdate`或`Recreate`。

`Recreate`是一种非常基本的部署方法：部署中的所有 Pod 将同时被删除，并将使用新版本创建新的 Pod。`Recreate`不能给我们太多控制权来防止糟糕的部署 - 如果由于某种原因新的 Pod 无法启动，我们将被困在一个完全无法运行的应用程序中。

另一方面，使用`RollingUpdate`，部署速度较慢，但控制更加严格。首先，新应用程序将逐步推出，逐个 Pod。我们可以指定`maxSurge`和`maxUnavailable`的值来调整策略。

滚动更新的工作方式是这样的 - 当部署规范使用 Pod 容器的新版本进行更新时，部署将逐个关闭一个 Pod，创建一个新的带有新应用程序版本的 Pod，等待新的 Pod 根据就绪检查注册为`Ready`，然后继续下一个 Pod。

`maxSurge`和`maxUnavailable`参数允许您加快或减慢此过程。`maxUnavailable`允许您调整在部署过程中不可用的最大 Pod 数量。这可以是百分比或固定数量。`maxSurge`允许您调整在任何给定时间内可以创建的超出部署副本数量的最大 Pod 数量。与`maxUnavailable`一样，这可以是百分比或固定数量。

以下图表显示了`RollingUpdate`过程：

![图 4.2 - 部署的 RollingUpdate 过程](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cld-ntv-k8s/img/B14790_04_002.jpg)

图 4.2 - 部署的 RollingUpdate 过程

正如您所看到的，“滚动更新”过程遵循了几个关键步骤。部署尝试逐个更新 Pod。只有在成功更新一个 Pod 之后，更新才会继续到下一个 Pod。

## 使用命令控制部署。

正如我们所讨论的，我们可以通过简单地更新其 YAML 文件来更改我们的部署，使用声明性方法。然而，Kubernetes 还为我们提供了一些在`kubectl`中控制部署的特殊命令。

首先，Kubernetes 允许我们手动扩展部署-也就是说，我们可以编辑应该运行的副本数量。

要将我们的`myapp-deployment`扩展到五个副本，我们可以运行以下命令：

```
kubectl scale deployment myapp-deployment --replicas=5
```

同样，如果需要，我们可以将我们的`myapp-deployment`回滚到旧版本。为了演示这一点，首先让我们手动编辑我们的部署，以使用容器的新版本：

```
Kubectl set image deployment myapp-deployment myapp-container=busybox:1.2 –record=true
```

这个命令告诉 Kubernetes 将我们部署中容器的版本更改为 1.2。然后，我们的部署将按照前面的图表中的步骤来推出我们的更改。

现在，假设我们想回到之前更新容器图像版本之前的版本。我们可以使用`rollout undo`命令轻松实现这一点：

```
Kubectl rollout undo deployment myapp-deployment
```

在我们之前的情况下，我们只有两个版本，初始版本和我们更新容器的版本，但如果有其他版本，我们可以在`undo`命令中指定它们，就像这样：

```
Kubectl rollout undo deployment myapp-deployment –to-revision=10
```

这应该让您对为什么部署如此有价值有所了解-它们为我们提供了对应用程序新版本的推出的精细控制。接下来，我们将讨论一个与部署和副本集协同工作的 Kubernetes 智能缩放器。

# 利用水平 Pod 自动缩放器

正如我们所看到的，部署和副本集允许您指定应在某个时间可用的副本的总数。然而，这些结构都不允许自动缩放-它们必须手动缩放。

水平 Pod 自动缩放器（HPA）通过作为更高级别的控制器存在，可以根据 CPU 和内存使用等指标改变部署或副本集的副本数量来提供这种功能。

默认情况下，HPA 可以根据 CPU 利用率进行自动缩放，但通过使用自定义指标，可以扩展此功能。

HPA 的 YAML 文件如下所示：

hpa.yaml

```
apiVersion: autoscaling/v1
kind: HorizontalPodAutoscaler
metadata:
  name: myapp-hpa
spec:
  maxReplicas: 5
  minReplicas: 2
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: myapp-deployment
  targetCPUUtilizationPercentage: 70
```

在上述规范中，我们有`scaleTargetRef`，它指定了 HPA 应该自动缩放的内容，以及调整参数。

`scaleTargetRef`的定义可以是部署（Deployment）、副本集（ReplicaSet）或复制控制器（ReplicationController）。在这种情况下，我们已经定义了 HPA 来扩展我们之前创建的部署`myapp-deployment`。

对于调整参数，我们使用默认的基于 CPU 利用率的扩展，因此我们可以使用`targetCPUUtilizationPercentage`来定义运行我们应用程序的每个 Pod 的预期 CPU 利用率。如果我们的 Pod 的平均 CPU 使用率超过 70%，我们的 HPA 将扩展部署规范，如果它长时间下降到以下水平，它将缩小部署。

典型的扩展事件看起来像这样：

1.  部署的平均 CPU 使用率超过了三个副本的 70%。

1.  HPA 控制循环注意到 CPU 利用率的增加。

1.  HPA 使用新的副本计数编辑部署规范。这个计数是基于 CPU 利用率计算的，目的是使每个节点的 CPU 使用率保持在 70%以下的稳定状态。

1.  部署控制器启动一个新的副本。

1.  这个过程会重复自身来扩展或缩小部署。

总之，HPA 跟踪 CPU 和内存利用率，并在超出边界时启动扩展事件。接下来，我们将审查 DaemonSets，它们提供了一种非常特定类型的 Pod 控制器。

# 实施 DaemonSets

从现在到本章结束，我们将审查更多关于具有特定要求的应用程序运行的小众选项。

我们将从 DaemonSets 开始，它们类似于 ReplicaSets，只是副本的数量固定为每个节点一个副本。这意味着集群中的每个节点将始终保持应用程序的一个副本处于活动状态。

重要说明

重要的是要记住，在没有额外的 Pod 放置控制（如污点或节点选择器）的情况下，这个功能只会在每个节点上创建一个副本，我们将在*第八章*中更详细地介绍*Pod 放置控制*。

这最终看起来像典型 DaemonSet 的下图所示：

![图 4.3 - DaemonSet 分布在三个节点上](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cld-ntv-k8s/img/B14790_04_003.jpg)

图 4.3 - DaemonSet 分布在三个节点上

正如您在上图中所看到的，每个节点（由方框表示）包含一个由 DaemonSet 控制的应用程序的 Pod。

这使得 DaemonSets 非常适合在节点级别收集指标或在每个节点上提供网络处理。DaemonSet 规范看起来像这样：

daemonset-1.yaml

```
apiVersion: apps/v1 
kind: DaemonSet
metadata:
  name: log-collector
spec:
  selector:
      matchLabels:
        name: log-collector   
  template:
    metadata:
      labels:
        name: log-collector
    spec:
      containers:
      - name: fluentd
        image: fluentd
```

如您所见，这与您典型的 ReplicaSet 规范非常相似，只是我们没有指定副本的数量。这是因为 DaemonSet 会尝试在集群中的每个节点上运行一个 Pod。

如果您想指定要运行应用程序的节点子集，可以使用节点选择器，如下面的文件所示：

daemonset-2.yaml

```
apiVersion: apps/v1 
kind: DaemonSet
metadata:
  name: log-collector
spec:
  selector:
      matchLabels:
        name: log-collector   
  template:
    metadata:
      labels:
        name: log-collector
    spec:
      nodeSelector:
        type: bigger-node 
      containers:
      - name: fluentd
        image: fluentd
```

这个 YAML 将限制我们的 DaemonSet 只能在其标签中匹配`type=bigger-node`的节点上运行。我们将在*第八章*中更多地了解有关节点选择器的信息，*Pod 放置控制*。现在，让我们讨论一种非常适合运行有状态应用程序（如数据库）的控制器类型 - StatefulSet。

# 理解 StatefulSets

StatefulSets 与 ReplicaSets 和 Deployments 非常相似，但有一个关键的区别，使它们更适合有状态的工作负载。StatefulSets 保持每个 Pod 的顺序和标识，即使 Pod 被重新调度到新节点上。

例如，在一个有 3 个副本的 StatefulSet 中，将始终存在 Pod 1、Pod 2 和 Pod 3，并且这些 Pod 将在 Kubernetes 和存储中保持它们的标识（我们将在*第七章*中介绍，*Kubernetes 上的存储*），无论发生任何重新调度。

让我们来看一个简单的 StatefulSet 配置：

statefulset.yaml

```
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: stateful
spec:
  selector:
    matchLabels:
      app: stateful-app
  replicas: 5
  template:
    metadata:
      labels:
        app: stateful-app
    spec:
      containers:
      - name: app
        image: busybox
```

这个 YAML 将创建一个具有五个应用程序副本的 StatefulSet。

让我们看看 StatefulSet 如何与典型的 Deployment 或 ReplicaSet 不同地维护 Pod 标识。让我们使用以下命令获取所有 Pods：

```
kubectl get pods
```

输出应如下所示：

```
NAME      		   READY     STATUS    RESTARTS   AGE
stateful-app-0     1/1       Running   0         55s
stateful-app-1     1/1       Running   0         48s
stateful-app-2     1/1       Running   0         26s
stateful-app-3     1/1       Running   0         18s
stateful-app-4     0/1       Pending   0         3s
```

如您所见，在这个例子中，我们有五个 StatefulSet Pods，每个都有一个数字指示其标识。这个属性对于有状态的应用程序非常有用，比如数据库集群。在 Kubernetes 上运行数据库集群时，主 Pod 与副本 Pod 的标识很重要，我们可以使用 StatefulSet 标识来轻松管理它。

另一个有趣的地方是，您可以看到最终的 Pod 仍在启动，并且随着数字标识的增加，Pod 的年龄也在增加。这是因为 StatefulSet Pods 是按顺序逐个创建的。

StatefulSets 在持久的 Kubernetes 存储中非常有价值，以便运行有状态的应用程序。我们将在第七章《Kubernetes 上的存储》中了解更多相关内容，但现在让我们讨论另一个具有非常特定用途的控制器：Jobs。

# 使用 Jobs

Kubernetes 中 Job 资源的目的是运行可以完成的任务，这使它们不太适合长时间运行的应用程序，但非常适合批处理作业或类似任务，可以从并行性中受益。

以下是 Job 规范 YAML 的样子：

job-1.yaml

```
apiVersion: batch/v1
kind: Job
metadata:
  name: runner
spec:
  template:
    spec:
      containers:
      - name: run-job
        image: node:lts-jessie
        command: ["node", "job.js"]
      restartPolicy: Never
  backoffLimit: 4
```

这个 Job 将启动一个单独的 Pod，并运行一个命令 `node job.js`，直到完成，然后 Pod 将关闭。在这个和未来的示例中，我们假设使用的容器镜像有一个名为 `job.js` 的文件，其中包含了作业逻辑。`node:lts-jessie` 容器镜像默认情况下不会有这个文件。这是一个不使用并行性运行的 Job 的示例。正如您可能从 Docker 的使用中知道的那样，多个命令参数必须作为字符串数组传递。

为了创建一个可以并行运行的 Job（也就是说，多个副本同时运行 Job），您需要以一种可以在结束进程之前告诉它 Job 已完成的方式来开发应用程序代码。为了做到这一点，每个 Job 实例都需要包含代码，以确保它执行更大批处理任务的正确部分，并防止发生重复工作。

有几种应用程序模式可以实现这一点，包括互斥锁和工作队列。此外，代码需要检查整个批处理任务的状态，这可能需要通过更新数据库中的值来处理。一旦 Job 代码看到更大的任务已经完成，它就应该退出。

完成后，您可以使用 `parallelism` 键向作业代码添加并行性。以下代码块显示了这一点：

job-2.yaml

```
apiVersion: batch/v1
kind: Job
metadata:
  name: runner
spec:
  parallelism: 3
  template:
    spec:
      containers:
      - name: run-job
        image: node:lts-jessie
        command: ["node", "job.js"]
      restartPolicy: Never
  backoffLimit: 4
```

如您所见，我们使用 `parallelism` 键添加了三个副本。此外，您可以将纯作业并行性替换为指定数量的完成次数，在这种情况下，Kubernetes 可以跟踪 Job 已完成的次数。您仍然可以为此设置并行性，但如果不设置，它将默认为 1。

下一个规范将运行一个 Job 完成 4 次，每次运行 2 次迭代：

job-3.yaml

```
apiVersion: batch/v1
kind: Job
metadata:
  name: runner
spec:
  parallelism: 2
  completions: 4
  template:
    spec:
      containers:
      - name: run-job
        image: node:lts-jessie
        command: ["node", "job.js"]
      restartPolicy: Never
  backoffLimit: 4
```

Kubernetes 上的作业提供了一种很好的方式来抽象一次性进程，并且许多第三方应用程序将它们链接到工作流中。正如你所看到的，它们非常容易使用。

接下来，让我们看一个非常相似的资源，CronJob。

## CronJobs

CronJobs 是用于定时作业执行的 Kubernetes 资源。这与你可能在你喜欢的编程语言或应用程序框架中找到的 CronJob 实现非常相似，但有一个关键的区别。Kubernetes CronJobs 触发 Kubernetes Jobs，这提供了一个额外的抽象层，可以用来触发每天晚上的批处理作业。

Kubernetes 中的 CronJobs 使用非常典型的 cron 表示法进行配置。让我们来看一下完整的规范：

cronjob-1.yaml

```
apiVersion: batch/v1beta1
kind: CronJob
metadata:
  name: hello
spec:
  schedule: "0 1 * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
           - name: run-job
             image: node:lts-jessie
             command: ["node", "job.js"]
          restartPolicy: OnFailure
```

这个 CronJob 将在每天凌晨 1 点创建一个与我们之前的 Job 规范相同的 Job。要快速查看 cron 时间表示法，以解释我们凌晨 1 点工作的语法，请继续阅读。要全面了解 cron 表示法，请查看[`man7.org/linux/man-pages/man5/crontab.5.html`](http://man7.org/linux/man-pages/man5/crontab.5.html)。

Cron 表示法由五个值组成，用空格分隔。每个值可以是数字整数、字符或组合。这五个值中的每一个代表一个时间值，格式如下，从左到右：

+   分钟

+   小时

+   一个月中的某一天（比如`25`）

+   月

+   星期几（例如，`3` = 星期三）

之前的 YAML 假设了一个非并行的 CronJob。如果我们想增加 CronJob 的批处理能力，我们可以像之前的作业规范一样添加并行性。以下代码块显示了这一点：

cronjob-2.yaml

```
apiVersion: batch/v1beta1
kind: CronJob
metadata:
  name: hello
spec:
  schedule: "0 1 * * *"
  jobTemplate:
    spec:
      parallelism: 3
      template:
        spec:
          containers:
           - name: run-job
             image: node:lts-jessie
             command: ["node", "job.js"]
          restartPolicy: OnFailure
```

请注意，为了使其工作，你的 CronJob 容器中的代码需要优雅地处理并行性，这可以使用工作队列或其他类似的模式来实现。

我们现在已经审查了 Kubernetes 默认提供的所有基本控制器。让我们利用我们的知识，在下一节中运行一个更复杂的应用程序示例在 Kubernetes 上。

# 把所有这些放在一起

我们现在有了在 Kubernetes 上运行应用程序的工具集。让我们看一个真实的例子，看看如何将所有这些组合起来运行一个具有多个层和功能分布在 Kubernetes 资源上的应用程序：

![图 4.4 - 多层应用程序图表](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cld-ntv-k8s/img/B14790_04_004.jpg)

图 4.4 - 多层应用程序图表

正如您在前面的代码中所看到的，我们的示例应用程序包含一个运行.NET Framework 应用程序的 Web 层，一个运行 Java 的中间层或服务层，一个运行 Postgres 的数据库层，最后是一个日志/监控层。

我们对每个层级的控制器选择取决于我们计划在每个层级上运行的应用程序。对于 Web 层和中间层，我们运行无状态应用程序和服务，因此我们可以有效地使用 Deployments 来处理更新、蓝/绿部署等。

对于数据库层，我们需要我们的数据库集群知道哪个 Pod 是副本，哪个是主节点 - 因此我们使用 StatefulSet。最后，我们的日志收集器需要在每个节点上运行，因此我们使用 DaemonSet 来运行它。

现在，让我们逐个查看每个层级的示例 YAML 规范。

让我们从基于 JavaScript 的 Web 应用程序开始。通过在 Kubernetes 上托管此应用程序，我们可以进行金丝雀测试和蓝/绿部署。需要注意的是，本节中的一些示例使用在 DockerHub 上不公开可用的容器映像名称。要使用此模式，请将示例调整为您自己的应用程序容器，或者如果您想在没有实际应用程序逻辑的情况下运行它，只需使用 busybox。

Web 层的 YAML 文件可能如下所示：

example-deployment-web.yaml

```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: webtier-deployment
  labels:
    tier: web
spec:
  replicas: 10
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 50%
      maxUnavailable: 25% 
  selector:
    matchLabels:
      tier: web
  template:
    metadata:
      labels:
        tier: web
    spec:
      containers:
      - name: reactapp-container
        image: myreactapp
```

在前面的 YAML 中，我们使用`tier`标签对我们的应用程序进行标记，并将其用作我们的`matchLabels`选择器。

接下来是中间层服务层。让我们看看相关的 YAML：

example-deployment-mid.yaml

```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: midtier-deployment
  labels:
    tier: mid
spec:
  replicas: 8
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 25%
      maxUnavailable: 25% 
  selector:
    matchLabels:
      tier: mid
  template:
    metadata:
      labels:
        tier: mid
    spec:
      containers:
      - name: myjavaapp-container
        image: myjavaapp
```

正如您在前面的代码中所看到的，我们的中间层应用程序与 Web 层设置非常相似，并且我们使用了另一个 Deployment。

现在是有趣的部分 - 让我们来看看我们的 Postgres StatefulSet 的规范。我们已经在这个代码块中进行了一些截断，以便适应页面，但您应该能够看到最重要的部分：

example-statefulset.yaml

```
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: postgres-db
  labels:
    tier: db
spec:
  serviceName: "postgres"
  replicas: 2
  selector:
    matchLabels:
      tier: db
  template:
    metadata:
      labels:
        tier: db
    spec:
      containers:
      - name: postgres
        image: postgres:latest
        envFrom:
          - configMapRef:
              name: postgres-conf
        volumeMounts:
        - name: pgdata
          mountPath: /var/lib/postgresql/data
          subPath: postgres
```

在前面的 YAML 文件中，我们可以看到一些我们尚未审查的新概念 - ConfigMaps 和卷。我们将在*第六章*，*Kubernetes 应用程序配置*和*第七章*，*Kubernetes 上的存储*中更仔细地了解它们的工作原理，但现在让我们专注于规范的其余部分。我们有我们的`postgres`容器以及在默认的 Postgres 端口`5432`上设置的端口。

最后，让我们来看看我们的日志应用程序的 DaemonSet。这是 YAML 文件的一部分，我们为了长度又进行了截断：

example-daemonset.yaml

```
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: fluentd
  namespace: kube-system
  labels:
    tier: logging
spec:
  updateStrategy:
    type: RollingUpdate
  template:
    metadata:
      labels:
        tier: logging
    spec:
      tolerations:
      - key: node-role.kubernetes.io/master
        effect: NoSchedule
      containers:
      - name: fluentd
        image: fluent/fluentd-kubernetes-daemonset:v1-debian-papertrail
        env:
          - name: FLUENT_PAPERTRAIL_HOST
            value: "mycompany.papertrailapp.com"
          - name: FLUENT_PAPERTRAIL_PORT
            value: "61231"
          - name: FLUENT_HOSTNAME
            value: "DEV_CLUSTER"
```

在这个 DaemonSet 中，我们正在设置 FluentD（一个流行的开源日志收集器）将日志转发到 Papertrail，一个基于云的日志收集器和搜索工具。同样，在这个 YAML 文件中，有一些我们以前没有审查过的内容。例如，`tolerations`部分用于`node-role.kubernetes.io/master`，实际上允许我们的 DaemonSet 将 Pod 放置在主节点上，而不仅仅是工作节点上。我们将在*第八章* *Pod 放置控制*中审查这是如何工作的。

我们还在 Pod 规范中直接指定环境变量，这对于相对基本的配置来说是可以的，但是可以通过使用 Secrets 或 ConfigMaps（我们将在*第六章* *Kubernetes 应用配置*中进行审查）来改进，以避免将其放入我们的 YAML 代码中。

# 摘要

在本章中，我们回顾了在 Kubernetes 上运行应用程序的一些方法。首先，我们回顾了为什么 Pod 本身不足以保证应用程序的可用性，并介绍了控制器。然后，我们回顾了一些简单的控制器，包括 ReplicaSets 和 Deployments，然后转向具有更具体用途的控制器，如 HPAs、Jobs、CronJobs、StatefulSets 和 DaemonSets。最后，我们将所有学到的知识应用到了在 Kubernetes 上运行复杂应用程序的实现中。

在下一章中，我们将学习如何使用 Services 和 Ingress 将我们的应用程序（现在具有高可用性）暴露给世界。

# 问题

1.  ReplicaSet 和 ReplicationController 之间有什么区别？

1.  Deployment 相对于 ReplicaSet 的优势是什么？

1.  什么是 Job 的一个很好的用例？

1.  为什么 StatefulSets 对有状态的工作负载更好？

1.  我们如何使用 Deployments 支持金丝雀发布流程？

# 进一步阅读

+   官方 Kubernetes 文档：[`kubernetes.io/docs/home/`](https://kubernetes.io/docs/home/)

+   Kubernetes Job 资源的文档：[`kubernetes.io/docs/concepts/workloads/controllers/job/`](https://kubernetes.io/docs/concepts/workloads/controllers/job/)

+   FluentD DaemonSet 安装文档：[`github.com/fluent/fluentd-kubernetes-daemonset`](https://github.com/fluent/fluentd-kubernetes-daemonset)

+   *Kubernetes The Hard Way*: [`github.com/kelseyhightower/kubernetes-the-hard-way`](https://github.com/kelseyhightower/kubernetes-the-hard-way)
