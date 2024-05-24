# Kubernetes 云原生指南（三）

> 原文：[`zh.annas-archive.org/md5/58DD843CC49B42503E619A37722EEB6C`](https://zh.annas-archive.org/md5/58DD843CC49B42503E619A37722EEB6C)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三部分：在生产环境中运行 Kubernetes

在本节中，您将了解 Kubernetes 的第 2 天运维、CI/CD 的最佳实践、如何定制和扩展 Kubernetes，以及更广泛的云原生生态系统的基础知识。

本书的这一部分包括以下章节：

+   第九章，Kubernetes 的可观察性

+   第十章，Kubernetes 故障排除

+   第十一章，模板代码生成和 Kubernetes 上的 CI/CD

+   第十二章，Kubernetes 安全性和合规性


# 第九章：Kubernetes 上的可观测性

本章深入讨论了在生产环境中运行 Kubernetes 时强烈建议实施的能力。首先，我们讨论了在分布式系统（如 Kubernetes）的上下文中的可观测性。然后，我们看一下内置的 Kubernetes 可观测性堆栈以及它实现的功能。最后，我们学习如何通过生态系统中的额外可观测性、监控、日志记录和指标基础设施来补充内置的可观测性工具。本章中学到的技能将帮助您将可观测性工具部署到您的 Kubernetes 集群，并使您能够了解您的集群（以及在其上运行的应用程序）的运行方式。

在本章中，我们将涵盖以下主题：

+   在 Kubernetes 上理解可观测性

+   使用默认的可观测性工具 - 指标、日志和仪表板

+   实施生态系统的最佳实践

首先，我们将学习 Kubernetes 为可观测性提供的开箱即用工具和流程。

# 技术要求

为了运行本章中详细介绍的命令，您需要一台支持`kubectl`命令行工具的计算机，以及一个正常运行的 Kubernetes 集群。请参阅*第一章*，*与 Kubernetes 通信*，了解快速启动和安装 kubectl 工具的几种方法。

本章中使用的代码可以在该书的 GitHub 存储库中找到：

[`github.com/PacktPublishing/Cloud-Native-with-Kubernetes/tree/master/Chapter9`](https://github.com/PacktPublishing/Cloud-Native-with-Kubernetes/tree/master/Chapter9)

# 在 Kubernetes 上理解可观测性

没有监控的生产系统是不完整的。在软件中，我们将可观测性定义为在任何时间点都能够了解系统的性能（在最好的情况下，还能了解原因）。可观测性在安全性、性能和运行能力方面带来了显著的好处。通过了解您的系统在虚拟机、容器和应用程序级别的响应方式，您可以调整它以高效地运行，快速响应事件，并更容易地排除错误。

例如，让我们来看一个场景，您的应用程序运行非常缓慢。为了找到瓶颈，您可能会查看应用程序代码本身，Pod 的资源规格，部署中的 Pod 数量，Pod 级别或节点级别的内存和 CPU 使用情况，以及外部因素，比如在集群外运行的 MySQL 数据库。

通过添加可观察性工具，您将能够诊断许多这些变量，并找出可能导致应用程序减速的问题。

Kubernetes 作为一个成熟的容器编排系统，为我们提供了一些默认工具来监控我们的应用程序。在本章中，我们将把可观察性分为四个概念：指标、日志、跟踪和警报。让我们来看看每一个：

+   **指标**在这里代表着查看系统当前状态的数值表示能力，特别关注 CPU、内存、网络、磁盘空间等。这些数字让我们能够判断当前状态与系统最大容量之间的差距，并确保系统对用户保持可用。

+   **日志**指的是从应用程序和系统中收集文本日志的做法。日志可能是 Kubernetes 控制平面日志和应用程序 Pod 自身的日志的组合。日志可以帮助我们诊断 Kubernetes 系统的可用性，但它们也可以帮助我们排除应用程序错误。

+   **跟踪**指的是收集分布式跟踪。跟踪是一种可观察性模式，提供了对请求链的端到端可见性 - 这些请求可以是 HTTP 请求或其他类型的请求。在使用微服务的分布式云原生环境中，这个主题尤为重要。如果您有许多微服务并且它们相互调用，那么在涉及多个服务的单个端到端请求时，很难找到瓶颈或问题。跟踪允许您查看每个服务对服务调用的每个环节分解的请求。

+   **警报**对应于在发生某些事件时设置自动触点的做法。警报可以设置在*指标*和*日志*上，并通过各种媒介传递，从短信到电子邮件再到第三方应用程序等等。

在这四个可观测性方面之间，我们应该能够了解我们集群的健康状况。然而，可以配置许多不同的可能的指标、日志甚至警报。因此，了解要寻找的内容非常重要。下一节将讨论 Kubernetes 集群和应用程序健康最重要的可观测性领域。

## 了解对 Kubernetes 集群和应用程序健康至关重要的内容

在 Kubernetes 或第三方可观测性解决方案提供的大量可能的指标和日志中，我们可以缩小一些最有可能导致集群出现重大问题的指标。无论您最终选择使用哪种可观测性解决方案，您都应该将这些要点放在最显眼的位置。首先，让我们看一下 CPU 使用率与集群健康之间的关系。

### 节点 CPU 使用率

在您的可观测性解决方案中，跨 Kubernetes 集群节点的 CPU 使用率状态是一个非常重要的指标。我们在之前的章节中已经讨论过，Pod 可以为 CPU 使用率定义资源请求和限制。然而，当限制设置得比集群的最大 CPU 容量更高时，节点仍然可能过度使用 CPU。此外，运行我们控制平面的主节点也可能遇到 CPU 容量问题。

CPU 使用率达到最大的工作节点可能会表现不佳，或者限制运行在 Pod 上的工作负载。如果 Pod 上没有设置限制，或者节点的总 Pod 资源限制大于其最大容量，即使其总资源请求较低，也很容易发生这种情况。CPU 使用率达到最大的主节点可能会影响调度器、kube-apiserver 或其他控制平面组件的性能。

总的来说，工作节点和主节点的 CPU 使用率应该在您的可观测性解决方案中可见。最好的方法是通过一些指标（例如在本章后面将要介绍的 Grafana 等图表解决方案）以及对集群中节点的高 CPU 使用率的警报来实现。

内存使用率也是一个非常重要的指标，与 CPU 类似，需要密切关注。

### 节点内存使用率

与 CPU 使用率一样，内存使用率也是集群中需要密切观察的一个极其重要的指标。内存使用率可以通过 Pod 资源限制进行过度使用，对于集群中的主节点和工作节点都可能出现与 CPU 使用率相同的问题。

同样，警报和指标的组合对于查看集群内存使用情况非常重要。我们将在本章后面学习一些工具。

下一个重要的可观察性部分，我们将不再关注指标，而是关注日志。

### 控制平面日志记录

### 当运行时，Kubernetes 控制平面的组件会输出日志，这些日志可以用于深入了解集群操作。正如我们将在《第十章》*Chapter 10*中看到的那样，这些日志也可以在故障排除中起到重要作用，*故障排除 Kubernetes*。Kubernetes API 服务器、控制器管理器、调度程序、kube 代理和 kubelet 的日志对于某些故障排除或可观察性原因都非常有用。

### 应用程序日志记录

应用程序日志记录也可以并入 Kubernetes 的可观察性堆栈中——能够查看应用程序日志以及其他指标可能对操作员非常有帮助。

### 应用程序性能指标

与应用程序日志记录一样，应用程序性能指标和监控对于在 Kubernetes 上运行的应用程序的性能非常重要。在应用程序级别进行内存使用和 CPU 分析可以成为可观察性堆栈中有价值的一部分。

一般来说，Kubernetes 提供了应用程序监控和日志记录的数据基础设施，但不提供诸如图表和搜索等更高级的功能。考虑到这一点，让我们回顾一下 Kubernetes 默认提供的工具，以解决这些问题。

# 使用默认的可观察性工具

Kubernetes 甚至在不添加任何第三方解决方案的情况下就提供了可观察性工具。这些本机 Kubernetes 工具构成了许多更强大解决方案的基础，因此讨论它们非常重要。由于可观察性包括指标、日志、跟踪和警报，我们将依次讨论每个内容，首先关注 Kubernetes 本机解决方案。首先，让我们讨论指标。

## Kubernetes 上的指标

通过简单运行`kubectl describe pod`，可以获得关于应用程序的大量信息。我们可以看到有关 Pod 规范的信息，它所处的状态以及阻止其功能的关键问题。

假设我们的应用程序出现了一些问题。具体来说，Pod 没有启动。为了调查，我们运行`kubectl describe pod`。作为*第一章*中提到的 kubectl 别名的提醒，`kubectl describe pod`与`kubectl describe pods`是相同的。这是`describe pod`命令的一个示例输出 - 我们除了`Events`信息之外剥离了所有内容：

![图 9.1 - 描述 Pod 事件输出](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cld-ntv-k8s/img/B14790_09_001_new.jpg)

图 9.1 - 描述 Pod 事件输出

正如您所看到的，这个 Pod 没有被调度，因为我们的 Nodes 都没有内存了！这将是一个值得进一步调查的好事。

让我们继续。通过运行`kubectl describe nodes`，我们可以了解很多关于我们的 Kubernetes Nodes 的信息。其中一些信息对我们系统的性能非常重要。这是另一个示例输出，这次是来自`kubectl describe nodes`命令。而不是将整个输出放在这里，因为可能会相当冗长，让我们聚焦在两个重要部分 - `Conditions`和`Allocated resources`。首先，让我们回顾一下`Conditions`部分：

![图 9.2 - 描述 Node 条件输出](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cld-ntv-k8s/img/B14790_09_002_new.jpg)

图 9.2 - 描述 Node 条件输出

正如您所看到的，我们已经包含了`kubectl describe nodes`命令输出的`Conditions`块。这是查找任何问题的好地方。正如我们在这里看到的，我们的 Node 实际上正在遇到问题。我们的`MemoryPressure`条件为 true，而`Kubelet`内存不足。难怪我们的 Pod 无法调度！

接下来，检查`分配的资源`块：

```
Allocated resources:
 (Total limits may be over 100 percent, i.e., overcommitted.)
 CPU Requests	CPU Limits    Memory Requests  Memory Limits
 ------------	----------    ---------------  -------------
 8520m (40%)	4500m (24%)   16328Mi (104%)   16328Mi (104%)
```

现在我们看到了一些指标！看起来我们的 Pod 正在请求过多的内存，导致我们的 Node 和 Pod 出现问题。从这个输出中可以看出，Kubernetes 默认已经在收集有关我们的 Nodes 的指标数据。没有这些数据，调度器将无法正常工作，因为维护 Pod 资源请求与 Node 容量是其最重要的功能之一。

然而，默认情况下，这些指标不会向用户显示。实际上，它们是由每个 Node 的`Kubelet`收集并传递给调度器来完成其工作。幸运的是，我们可以通过部署 Metrics Server 轻松地获取这些指标到我们的集群中。

Metrics Server 是一个官方支持的 Kubernetes 应用程序，它收集指标信息并在 API 端点上公开它以供使用。实际上，Metrics Server 是使水平 Pod 自动缩放器工作所必需的，但它并不总是默认包含在内，这取决于 Kubernetes 发行版。

部署 Metrics Server 非常快速。在撰写本书时，可以使用以下命令安装最新版本：

```
kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/download/v0.3.7/components.yaml
```

重要说明

有关如何使用 Metrics Server 的完整文档可以在[`github.com/kubernetes-sigs/metrics-server`](https://github.com/kubernetes-sigs/metrics-server)找到。

一旦 Metrics Server 运行起来，我们就可以使用一个全新的 Kubernetes 命令。`kubectl top`命令可用于 Pod 或节点，以查看有关内存和 CPU 使用量的详细信息。

让我们看一些示例用法。运行`kubectl top nodes`以查看节点级别的指标。以下是命令的输出：

![图 9.3-节点指标输出](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cld-ntv-k8s/img/B14790_09_003_new.jpg)

图 9.3-节点指标输出

正如您所看到的，我们能够看到绝对和相对的 CPU 和内存使用情况。

重要说明

CPU 核心以`millcpu`或`millicores`来衡量。1000`millicores`相当于一个虚拟 CPU。内存以字节为单位。

接下来，让我们来看一下`kubectl top pods`命令。使用`-namespace kube-system`标志运行它，以查看`kube-system`命名空间中的 Pod。

为此，我们运行以下命令：

```
Kubectl top pods -n kube-system 
```

然后我们得到以下输出：

```
NAMESPACE     NAME                CPU(cores)   MEMORY(bytes)   
default       my-hungry-pod       8m           50Mi            
default       my-lightweight-pod  2m           10Mi       
```

正如您所看到的，该命令使用与`kubectl top nodes`相同的绝对单位-毫核和字节。在查看 Pod 级别的指标时，没有相对百分比。

接下来，我们将看一下 Kubernetes 如何处理日志记录。

## Kubernetes 上的日志记录

我们可以将 Kubernetes 上的日志记录分为两个领域- *应用程序日志* 和 *控制平面日志*。让我们从控制平面日志开始。

### 控制平面日志

控制平面日志是指由 Kubernetes 控制平面组件（如调度程序、API 服务器等）创建的日志。对于纯净的 Kubernetes 安装，控制平面日志可以在节点本身找到，并且需要直接访问节点才能查看。对于设置为使用`systemd`的组件的集群，日志可以使用`journalctl`CLI 工具找到（有关更多信息，请参阅以下链接：[`manpages.debian.org/stretch/systemd/journalctl.1.en.html`](https://manpages.debian.org/stretch/systemd/journalctl.1.en.html)）。

在主节点上，您可以在文件系统的以下位置找到日志：

+   在`/var/log/kube-scheduler.log`中，您可以找到 Kubernetes 调度器的日志。

+   在`/var/log/kube-controller-manager.log`中，您可以找到控制器管理器的日志（例如，查看扩展事件）。

+   在`/var/log/kube-apiserver.log`中，您可以找到 Kubernetes API 服务器的日志。

在工作节点上，日志可以在文件系统的两个位置找到：

+   在`/var/log/kubelet.log`中，您可以找到 kubelet 的日志。

+   在`/var/log/kube-proxy.log`中，您可以找到 kube 代理的日志。

尽管通常情况下，集群健康受 Kubernetes 主节点和工作节点组件的影响，但跟踪应用程序日志也同样重要。

### 应用程序日志

在 Kubernetes 上查找应用程序日志非常容易。在我们解释它是如何工作之前，让我们看一个例子。

要检查特定 Pod 的日志，可以使用`kubectl logs <pod_name>`命令。该命令的输出将显示写入容器的`stdout`或`stderr`的任何文本。如果一个 Pod 有多个容器，您必须在命令中包含容器名称：

```
kubectl logs <pod_name> <container_name> 
```

在幕后，Kubernetes 通过使用容器引擎的日志驱动程序来处理 Pod 日志。通常，任何写入`stdout`或`stderr`的日志都会被持久化到每个节点的磁盘中的`/var/logs`文件夹中。根据 Kubernetes 的分发情况，可能会设置日志轮换，以防止日志占用节点磁盘空间过多。此外，Kubernetes 组件，如调度器、kubelet 和 kube-apiserver 也会将日志持久化到节点磁盘空间中，通常在`/var/logs`文件夹中。重要的是要注意默认日志记录功能的有限性 - Kubernetes 的强大可观察性堆栈肯定会包括第三方解决方案用于日志转发，我们很快就会看到。

接下来，对于一般的 Kubernetes 可观察性，我们可以使用 Kubernetes 仪表板。

## 安装 Kubernetes 仪表板

Kubernetes 仪表板提供了 kubectl 的所有功能，包括查看日志和编辑资源，都可以在图形界面中完成。设置仪表板非常容易，让我们看看如何操作。

仪表板可以通过单个`kubectl apply`命令安装。要进行自定义，请查看 Kubernetes 仪表板 GitHub 页面[`github.com/kubernetes/dashboard`](https://github.com/kubernetes/dashboard)。

要安装 Kubernetes 仪表板的版本，请运行以下`kubectl`命令，将`<VERSION>`标签替换为您所需的版本，根据您正在使用的 Kubernetes 版本（再次检查 Dashboard GitHub 页面以获取版本兼容性）：

```
kubectl apply -f https://raw.githubusercontent.com/kubernetes/dashboard/<VERSION> /aio/deploy/recommended.yaml
```

在我们的案例中，截至本书撰写时，我们将使用 v2.0.4 - 最终的命令看起来像这样：

```
kubectl apply -f https://raw.githubusercontent.com/kubernetes/dashboard/v2.0.4/aio/deploy/recommended.yaml
```

安装了 Kubernetes 仪表板后，有几种方法可以访问它。

重要提示

通常不建议使用 Ingress 或公共负载均衡器服务，因为 Kubernetes 仪表板允许用户更新集群对象。如果由于某种原因您的仪表板登录方法受到损害或容易被发现，您可能面临着很大的安全风险。

考虑到这一点，我们可以使用`kubectl port-forward`或`kubectl proxy`来从本地机器查看我们的仪表板。

在本例中，我们将使用`kubectl proxy`命令，因为我们还没有在示例中使用过它。

`kubectl proxy`命令与`kubectl port-forward`命令不同，它只需要一个命令即可代理到集群上运行的每个服务。它通过直接将 Kubernetes API 代理到本地机器上的一个端口来实现这一点，默认端口为`8081`。有关`kubectl proxy`命令的详细讨论，请查看[`kubernetes.io/docs/reference/generated/kubectl/kubectl-commands#proxy`](https://kubernetes.io/docs/reference/generated/kubectl/kubectl-commands#proxy)上的文档。

为了使用`kubectl proxy`访问特定的 Kubernetes 服务，您只需要正确的路径。运行`kubectl proxy`后访问 Kubernetes 仪表板的路径将如下所示：

```
http://localhost:8001/api/v1/namespaces/kubernetes-dashboard/services/https:kubernetes-dashboard:/proxy/
```

正如您所看到的，我们在浏览器中放置的`kubectl proxy`路径是在本地主机端口`8001`上，并提到了命名空间（`kubernetes-dashboard`）、服务名称和选择器（`https:kubernetes-dashboard`）以及代理路径。

让我们将 Kubernetes 仪表板的 URL 放入浏览器中并查看结果：

![图 9.4 - Kubernetes 仪表板登录](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cld-ntv-k8s/img/B14790_09_004_new.jpg)

图 9.4 - Kubernetes 仪表板登录

当我们部署和访问 Kubernetes 仪表板时，我们会看到一个登录界面。我们可以创建一个服务账户（或使用我们自己的）来登录仪表板，或者简单地链接我们的本地 `Kubeconfig` 文件。通过使用特定服务账户的令牌登录到 Kubernetes 仪表板，仪表板用户将继承该服务账户的权限。这允许您指定用户将能够使用 Kubernetes 仪表板执行哪种类型的操作 - 例如，只读权限。

让我们继续为我们的 Kubernetes 仪表板创建一个全新的服务账户。您可以自定义此服务账户并限制其权限，但现在我们将赋予它管理员权限。要做到这一点，请按照以下步骤操作：

1.  我们可以使用以下 Kubectl 命令来命令式地创建一个服务账户：

```
kubectl create serviceaccount dashboard-user
```

这将产生以下输出，确认了我们服务账户的创建：

```
serviceaccount/dashboard-user created
```

1.  现在，我们需要将我们的服务账户链接到一个 ClusterRole。您也可以使用 Role，但我们希望我们的仪表板用户能够访问所有命名空间。为了使用单个命令将服务账户链接到 `cluster-admin` 默认 ClusterRole，我们可以运行以下命令：

```
kubectl create clusterrolebinding dashboard-user \--clusterrole=cluster-admin --serviceaccount=default:dashboard-user
```

这个命令将产生以下输出：

```
clusterrolebinding.rbac.authorization.k8s.io/dashboard-user created
```

1.  运行此命令后，我们应该能够登录到我们的仪表板！首先，我们只需要找到我们将用于登录的令牌。服务账户的令牌存储为 Kubernetes 秘密，所以让我们看看它是什么样子。运行以下命令以查看我们的令牌存储在哪个秘密中：

```
kubectl get secrets
```

在输出中，您应该会看到一个类似以下的秘密：

```
NAME                         TYPE                                  DATA   AGE
dashboard-user-token-dcn2g   kubernetes.io/service-account-token   3      112s
```

1.  现在，为了获取我们用于登录到仪表板的令牌，我们只需要使用以下命令描述秘密内容：

```
kubectl describe secret dashboard-user-token-dcn2g   
```

生成的输出将如下所示：

```
Name:         dashboard-user-token-dcn2g
Namespace:    default
Labels:       <none>
Annotations:  kubernetes.io/service-account.name: dashboard-user
              kubernetes.io/service-account.uid: 9dd255sd-426c-43f4-88c7-66ss91h44215
Type:  kubernetes.io/service-account-token
Data
====
ca.crt:     1025 bytes
namespace:  7 bytes
token: < LONG TOKEN HERE >
```

1.  要登录到仪表板，复制`token`旁边的字符串，将其复制到 Kubernetes 仪表板登录界面上的令牌输入中，然后点击**登录**。您应该会看到 Kubernetes 仪表板概览页面！

1.  继续在仪表板上点击 - 您应该能够看到您可以使用 kubectl 查看的所有相同资源，并且您可以在左侧边栏中按命名空间进行过滤。例如，这是一个**命名空间**页面的视图：![图 9.5 - Kubernetes 仪表板详细信息](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cld-ntv-k8s/img/B14790_09_005_new.jpg)

图 9.5 - Kubernetes 仪表板详细信息

1.  您还可以单击单个资源，甚至使用仪表板编辑这些资源，只要您用于登录的服务帐户具有适当的权限。

这是从部署详细页面编辑部署资源的视图：

![图 9.6 – Kubernetes 仪表板编辑视图](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cld-ntv-k8s/img/B14790_09_006_new.jpg)

图 9.6 – Kubernetes 仪表板编辑视图

Kubernetes 仪表板还允许您查看 Pod 日志，并深入了解集群中的许多其他资源类型。要了解仪表板的全部功能，请查看先前提到的 GitHub 页面上的文档。

最后，为了完成我们对 Kubernetes 上默认可观察性的讨论，让我们来看一下警报。

## Kubernetes 上的警报和跟踪

不幸的是，可观察性谜题的最后两个部分——*警报*和*跟踪*——目前还不是 Kubernetes 上的本机功能。为了创建这种类型的功能，让我们继续我们的下一节——从 Kubernetes 生态系统中整合开源工具。

# 利用生态系统最佳增强 Kubernetes 的可观察性

正如我们所讨论的，尽管 Kubernetes 提供了强大的可见性功能的基础，但通常是由社区和供应商生态系统来创建用于度量、日志、跟踪和警报的高级工具。对于本书的目的，我们将专注于完全开源的自托管解决方案。由于许多这些解决方案在度量、日志、跟踪和警报之间满足多个可见性支柱的需求，因此在我们的审查过程中，我们将分别审查每个解决方案，而不是将解决方案分类到每个可见性支柱中。

让我们从用于度量和警报的技术常用组合**Prometheus**和**Grafana**开始。

## 介绍 Prometheus 和 Grafana

Prometheus 和 Grafana 是 Kubernetes 上典型的可见性技术组合。Prometheus 是一个时间序列数据库、查询层和具有许多集成的警报系统，而 Grafana 是一个复杂的图形和可视化层，与 Prometheus 集成。我们将带您了解这些工具的安装和使用，从 Prometheus 开始。

### 安装 Prometheus 和 Grafana

有许多在 Kubernetes 上安装 Prometheus 的方法，但大多数都使用部署来扩展服务。对于我们的目的，我们将使用 `kube-prometheus` 项目（[`github.com/coreos/kube-prometheus`](https://github.com/coreos/kube-prometheus)）。该项目包括一个 `operator` 以及几个**自定义资源定义**（**CRDs**）。它还将自动为我们安装 Grafana！

操作员本质上是 Kubernetes 上的一个应用控制器（像其他 Pod 中部署的应用程序一样部署），它恰好会向 Kubernetes API 发出命令，以便正确运行或操作其应用程序。

另一方面，CRD 允许我们在 Kubernetes API 内部建模自定义功能。我们将在*第十三章*中学到更多关于操作员和 CRDs 的知识，但现在只需将操作员视为创建*智能部署*的一种方式，其中应用程序可以正确地控制自身并根据需要启动其他 Pod 和部署 – 将 CRD 视为一种使用 Kubernetes 存储特定应用程序关注点的方式。

要安装 Prometheus，首先我们需要下载一个发布版，这可能会因 Prometheus 的最新版本或您打算使用的 Kubernetes 版本而有所不同：

```
curl -LO https://github.com/coreos/kube-prometheus/archive/v0.5.0.zip
```

接下来，使用任何工具解压文件。首先，我们需要安装 CRDs。一般来说，大多数 Kubernetes 工具安装说明都会让您首先在 Kubernetes 上创建 CRDs，因为如果底层 CRD 尚未在 Kubernetes 上创建，那么任何使用 CRD 的其他设置都将失败。

让我们使用以下命令安装它们：

```
kubectl apply -f manifests/setup
```

在创建 CRDs 时，我们需要等待几秒钟。此命令还将为我们的资源创建一个 `monitoring` 命名空间。一旦一切准备就绪，让我们使用以下命令启动其余的 Prometheus 和 Grafana 资源：

```
kubectl apply -f manifests/
```

让我们来谈谈这个命令实际上会创建什么。整个堆栈包括以下内容：

+   **Prometheus 部署**：Prometheus 应用程序的 Pod

+   **Prometheus 操作员**：控制和操作 Prometheus 应用程序 Pod

+   **Alertmanager 部署**：用于指定和触发警报的 Prometheus 组件

+   **Grafana**：一个强大的可视化仪表板

+   **Kube-state-metrics 代理**：从 Kubernetes API 状态生成指标

+   **Prometheus 节点导出器**：将节点硬件和操作系统级别的指标导出到 Prometheus

+   **用于 Kubernetes 指标的 Prometheus 适配器**：用于将 Kubernetes 资源指标 API 和自定义指标 API 摄入到 Prometheus 中

所有这些组件将为我们的集群提供复杂的可见性，从命令平面到应用程序容器本身。

一旦堆栈已经创建（通过使用`kubectl get po -n monitoring`命令进行检查），我们就可以开始使用我们的组件。让我们从简单的 Prometheus 开始使用。

### 使用 Prometheus

尽管 Prometheus 的真正力量在于其数据存储、查询和警报层，但它确实为开发人员提供了一个简单的 UI。正如您将在后面看到的，Grafana 提供了更多功能和自定义选项，但值得熟悉 Prometheus UI。

默认情况下，`kube-prometheus`只会为 Prometheus、Grafana 和 Alertmanager 创建 ClusterIP 服务。我们需要将它们暴露到集群外部。在本教程中，我们只是将服务端口转发到我们的本地机器。对于生产环境，您可能希望使用 Ingress 将请求路由到这三个服务。

为了`port-forward`到 Prometheus UI 服务，使用`port-forward` kubectl 命令：

```
Kubectl -n monitoring port-forward svc/prometheus-k8s 3000:9090
```

我们需要使用端口`9090`来访问 Prometheus UI。在您的机器上访问服务`http://localhost:3000`。

您应该看到类似以下截图的内容：

![图 9.7 – Prometheus UI](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cld-ntv-k8s/img/B14790_09_007_new.jpg)

图 9.7 – Prometheus UI

您可以看到，Prometheus UI 有一个**Graph**页面，这就是您在*图 9.4*中看到的内容。它还有自己的 UI 用于查看配置的警报 – 但它不允许您通过 UI 创建警报。Grafana 和 Alertmanager 将帮助我们完成这项任务。

要执行查询，导航到**Graph**页面，并将查询命令输入到**Expression**栏中，然后单击**Execute**。Prometheus 使用一种称为`PromQL`的查询语言 – 我们不会在本书中完全向您介绍它，但 Prometheus 文档是学习的好方法。您可以使用以下链接进行参考：[`prometheus.io/docs/prometheus/latest/querying/basics/`](https://prometheus.io/docs/prometheus/latest/querying/basics/)。

为了演示这是如何工作的，让我们输入一个基本的查询，如下所示：

```
kubelet_http_requests_total
```

此查询将列出每个节点上发送到 kubelet 的 HTTP 请求的总数，对于每个请求类别，如下截图所示：

![图 9.8 – HTTP 请求查询](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cld-ntv-k8s/img/B14790_09_008_new.jpg)

图 9.8 – HTTP 请求查询

您还可以通过单击**表**旁边的**图表**选项卡以图形形式查看请求，如下截图所示：

![图 9.9 – HTTP 请求查询 – 图表视图](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cld-ntv-k8s/img/B14790_09_009_new.jpg)

图 9.9 – HTTP 请求查询 – 图表视图

这提供了来自前面截图数据的时间序列图表视图。正如您所见，图表功能相当简单。

Prometheus 还提供了一个**警报**选项卡，用于配置 Prometheus 警报。通常，这些警报是通过代码配置而不是使用**警报**选项卡 UI 配置的，所以我们将在审查中跳过该页面。有关更多信息，您可以查看官方的 Prometheus 文档[`prometheus.io/docs/alerting/latest/overview/`](https://prometheus.io/docs/alerting/latest/overview/)。

让我们继续前往 Grafana，在那里我们可以通过可视化扩展 Prometheus 强大的数据工具。

### 使用 Grafana

Grafana 提供了强大的工具来可视化指标，支持许多可以实时更新的图表类型。我们可以将 Grafana 连接到 Prometheus，以便在 Grafana UI 上查看我们的集群指标图表。

要开始使用 Grafana，请执行以下操作：

1.  我们将结束当前的端口转发（*CTRL* + *C*即可），并设置一个新的端口转发监听器到 Grafana UI：

```
Kubectl -n monitoring port-forward svc/grafana 3000:3000
```

1.  再次导航到`localhost:3000`以查看 Grafana UI。您应该能够使用**用户名**：`admin`和**密码**：`admin`登录，然后您应该能够按照以下截图更改初始密码：![图 9.10 – Grafana 更改密码屏幕](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cld-ntv-k8s/img/B14790_09_010_new.jpg)

图 9.10 – Grafana 更改密码屏幕

1.  登录后，您将看到以下屏幕。Grafana 不会预先配置任何仪表板，但我们可以通过单击如下截图所示的**+**号轻松添加它们：![图 9.11 – Grafana 主页](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cld-ntv-k8s/img/B14790_09_011_new.jpg)

图 9.11 – Grafana 主页

1.  每个 Grafana 仪表板都包括一个或多个不同集合的指标图。要添加一个预配置的仪表板（而不是自己创建一个），请单击左侧菜单栏上的加号（**+**）并单击**导入**。您应该会看到以下截图所示的页面：![图 9.12 – Grafana 仪表板导入](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cld-ntv-k8s/img/B14790_09_012_new.jpg)

图 9.12 – Grafana 仪表板导入

我们可以通过此页面使用 JSON 配置或粘贴公共仪表板 ID 来添加仪表板。

1.  您可以在 [`grafana.com/grafana/dashboards/315`](https://grafana.com/grafana/dashboards/315) 找到公共仪表板及其关联的 ID。仪表板＃315 是 Kubernetes 的一个很好的起始仪表板 - 让我们将其添加到标有**Grafana.com 仪表板**的文本框中，然后单击**Load**。

1.  然后，在下一页中，从**Prometheus**选项下拉菜单中选择**Prometheus**数据源，用于在多个数据源之间进行选择（如果可用）。单击**Import**，应该加载仪表板，看起来像以下截图：

![图 9.13 – Grafana 仪表盘](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cld-ntv-k8s/img/B14790_09_013_new.jpg)

图 9.13 – Grafana 仪表盘

这个特定的 Grafana 仪表板提供了对集群中网络、内存、CPU 和文件系统利用率的良好高级概述，并且按照 Pod 和容器进行了细分。它配置了**网络 I/O 压力**、**集群内存使用**、**集群 CPU 使用**和**集群文件系统使用**的实时图表 - 尽管最后一个选项可能根据您安装 Prometheus 的方式而不启用。

最后，让我们看一下 Alertmanager UI。

### 使用 Alertmanager

Alertmanager 是一个用于管理从 Prometheus 警报生成的警报的开源解决方案。我们之前作为堆栈的一部分安装了 Alertmanager - 让我们看看它能做什么：

1.  首先，让我们使用以下命令`port-forward` Alertmanager 服务：

```
Kubectl -n monitoring port-forward svc/alertmanager-main 3000:9093
```

1.  像往常一样，导航到 `localhost:3000`，查看如下截图所示的 UI。它看起来与 Prometheus UI 类似：

![图 9.14 – Alertmanager UI](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cld-ntv-k8s/img/B14790_09_014_new.jpg)

图 9.14 – Alertmanager UI

Alertmanager 与 Prometheus 警报一起工作。您可以使用 Prometheus 服务器指定警报规则，然后使用 Alertmanager 将类似的警报分组为单个通知，执行去重，并创建*静音*，这实质上是一种静音警报的方式，如果它们符合特定规则。

接下来，我们将回顾 Kubernetes 的一个流行日志堆栈 - Elasticsearch、FluentD 和 Kibana。

## 在 Kubernetes 上实现 EFK 堆栈

类似于流行的 ELK 堆栈（Elasticsearch、Logstash 和 Kibana），EFK 堆栈将 Logstash 替换为 FluentD 日志转发器，在 Kubernetes 上得到了很好的支持。实现这个堆栈很容易，让我们可以使用纯开源工具在 Kubernetes 上开始日志聚合和搜索功能。

### 安装 EFK 堆栈

在 Kubernetes 上安装 EFK Stack 有很多种方法，但 Kubernetes GitHub 存储库本身有一些支持的 YAML，所以让我们就使用那个吧：

1.  首先，使用以下命令克隆或下载 Kubernetes 存储库：

```
git clone https://github.com/kubernetes/kubernetes
```

1.  清单位于`kubernetes/cluster/addons`文件夹中，具体位于`fluentd-elasticsearch`下：

```
cd kubernetes/cluster/addons
```

对于生产工作负载，我们可能会对这些清单进行一些更改，以便为我们的集群正确定制配置，但出于本教程的目的，我们将保留所有内容为默认值。让我们开始引导我们的 EFK 堆栈的过程。

1.  首先，让我们创建 Elasticsearch 集群本身。这在 Kubernetes 上作为一个 StatefulSet 运行，并提供一个 Service。要创建集群，我们需要运行两个`kubectl`命令：

```
kubectl apply -f ./fluentd-elasticsearch/es-statefulset.yaml
kubectl apply -f ./fluentd-elasticsearch/es-service.yaml
```

重要提示

关于 Elasticsearch StatefulSet 的一个警告 - 默认情况下，每个 Pod 的资源请求为 3GB 内存，因此如果您的节点没有足够的可用内存，您将无法按默认配置部署它。

1.  接下来，让我们部署 FluentD 日志代理。这些将作为一个 DaemonSet 运行 - 每个节点一个 - 并将日志从节点转发到 Elasticsearch。我们还需要创建包含基本 FluentD 代理配置的 ConfigMap YAML。这可以进一步定制以添加诸如日志过滤器和新来源之类的内容。

1.  要安装代理和它们的配置的 DaemonSet，请运行以下两个`kubectl`命令：

```
kubectl apply -f ./fluentd-elasticsearch/fluentd-es-configmap.yaml
kubectl apply -f ./fluentd-elasticsearch/fluentd-es-ds.yaml
```

1.  现在我们已经创建了 ConfigMap 和 FluentD DaemonSet，我们可以创建我们的 Kibana 应用程序，这是一个用于与 Elasticsearch 交互的 GUI。这一部分作为一个 Deployment 运行，带有一个 Service。要将 Kibana 部署到我们的集群，运行最后两个`kubectl`命令：

```
kubectl apply -f ./fluentd-elasticsearch/kibana-deployment.yaml
kubectl apply -f ./fluentd-elasticsearch/kibana-service.yaml
```

1.  一旦所有东西都已启动，这可能需要几分钟，我们就可以像我们之前对 Prometheus 和 Grafana 做的那样访问 Kibana UI。要检查我们刚刚创建的资源的状态，我们可以运行以下命令：

```
kubectl get po -A
```

1.  一旦 FluentD、Elasticsearch 和 Kibana 的所有 Pod 都处于**Ready**状态，我们就可以继续进行。如果您的任何 Pod 处于**Error**或**CrashLoopBackoff**阶段，请参阅`addons`文件夹中的 Kubernetes GitHub 文档以获取更多信息。

1.  一旦我们确认我们的组件正常工作，让我们使用`port-forward`命令来访问 Kibana UI。顺便说一句，我们的 EFK 堆栈组件将位于`kube-system`命名空间中 - 因此我们的命令需要反映这一点。因此，让我们使用以下命令：

```
kubectl port-forward -n kube-system svc/kibana-logging 8080:5601
```

这个命令将从 Kibana UI 开始一个`port-forward`到您本地机器的端口`8080`。

1.  让我们在`localhost:8080`上查看 Kibana UI。根据您的确切版本和配置，它应该看起来像下面这样：![图 9.15 – 基本 Kibana UI](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cld-ntv-k8s/img/B14790_09_015_new.jpg)

图 9.15 – 基本 Kibana UI

Kibana 为搜索和可视化日志、指标等提供了几种不同的功能。对于我们的目的来说，仪表板中最重要的部分是**日志**，因为在我们的示例中，我们仅将 Kibana 用作日志搜索 UI。

然而，Kibana 还有许多其他功能，其中一些与 Grafana 相当。例如，它包括一个完整的可视化引擎，**应用程序性能监控**（**APM**）功能，以及 Timelion，一个用于时间序列数据的表达式引擎，非常类似于 Prometheus 的 PromQL。Kibana 的指标功能类似于 Prometheus 和 Grafana。

1.  为了让 Kibana 工作，我们首先需要指定一个索引模式。要做到这一点，点击**可视化**按钮，然后点击**添加索引模式**。从模式列表中选择一个选项，并选择带有当前日期的索引，然后创建索引模式。

现在我们已经设置好了，**发现**页面将为您提供搜索功能。这使用 Apache Lucene 查询语法（[`www.elastic.co/guide/en/elasticsearch/reference/6.7/query-dsl-query-string-query.html#query-string-syntax`](https://www.elastic.co/guide/en/elasticsearch/reference/6.7/query-dsl-query-string-query.html#query-string-syntax)），可以处理从简单的字符串匹配表达式到非常复杂的查询。在下面的屏幕截图中，我们正在对字母`h`进行简单的字符串匹配。

![图 9.16 – 发现 UI](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cld-ntv-k8s/img/B14790_09_016_new.jpg)

图 9.16 – 发现 UI

当 Kibana 找不到任何结果时，它会为您提供一组方便的可能解决方案，包括查询示例，正如您在*图 9.13*中所看到的。

现在您已经知道如何创建搜索查询，可以在**可视化**页面上从查询中创建可视化。这些可视化可以从包括图形、图表等在内的可视化类型中选择，然后使用特定查询进行自定义，如下面的屏幕截图所示：

![图 9.17 – 新可视化](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cld-ntv-k8s/img/B14790_09_017_new.jpg)

图 9.17 – 新可视化

接下来，这些可视化可以组合成仪表板。这与 Grafana 类似，多个可视化可以添加到仪表板中，然后可以保存和重复使用。

您还可以使用搜索栏进一步过滤您的仪表板可视化 - 非常巧妙！下面的屏幕截图显示了如何将仪表板与特定查询关联起来：

![图 9.18 – 仪表板 UI](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cld-ntv-k8s/img/B14790_09_018_new.jpg)

图 9.18 – 仪表板 UI

如您所见，可以使用**添加**按钮为特定查询创建仪表板。

接下来，Kibana 提供了一个名为*Timelion*的工具，这是一个时间序列可视化综合工具。基本上，它允许您将单独的数据源合并到单个可视化中。Timelion 非常强大，但其功能集的全面讨论超出了本书的范围。下面的屏幕截图显示了 Timelion UI - 您可能会注意到与 Grafana 的一些相似之处，因为这两组工具提供了非常相似的功能：

![图 9.19 – Timelion UI](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cld-ntv-k8s/img/B14790_09_019_new.jpg)

图 9.19 – Timelion UI

如您所见，在 Timelion 中，查询可以用于驱动实时更新的图形，就像在 Grafana 中一样。

此外，虽然与本书关联较小，但 Kibana 提供了 APM 功能，这需要一些进一步的设置，特别是在 Kubernetes 中。在本书中，我们依赖 Prometheus 获取这种类型的信息，同时使用 EFK 堆栈搜索我们应用程序的日志。

现在我们已经介绍了用于度量和警报的 Prometheus 和 Grafana，以及用于日志记录的 EFK 堆栈，观察性谜题中只剩下一个部分。为了解决这个问题，我们将使用另一个优秀的开源软件 - Jaeger。

## 使用 Jaeger 实现分布式跟踪

Jaeger 是一个与 Kubernetes 兼容的开源分布式跟踪解决方案。Jaeger 实现了 OpenTracing 规范，这是一组用于定义分布式跟踪的标准。

Jaeger 提供了一个用于查看跟踪并与 Prometheus 集成的 UI。官方 Jaeger 文档可以在[`www.jaegertracing.io/docs/`](https://www.jaegertracing.io/docs/)找到。始终检查文档以获取新信息，因为自本书出版以来可能已经发生了变化。

### 使用 Jaeger Operator 安装 Jaeger

要安装 Jaeger，我们将使用 Jaeger Operator，这是本书中首次遇到的操作员。在 Kubernetes 中，*操作员*只是一种创建自定义应用程序控制器的模式，它们使用 Kubernetes 的语言进行通信。这意味着，您不必部署应用程序的各种 Kubernetes 资源，您可以部署一个单独的 Pod（通常是单个部署），该应用程序将与 Kubernetes 通信并为您启动所有其他所需的资源。它甚至可以进一步自我操作应用程序，在必要时进行资源更改。操作员可能非常复杂，但它们使我们作为最终用户更容易在我们的 Kubernetes 集群上部署商业或开源软件。

要开始使用 Jaeger Operator，我们需要为 Jaeger 创建一些初始资源，然后操作员将完成其余工作。安装 Jaeger 的先决条件是在我们的集群上安装了`nginx-ingress`控制器，因为这是我们将访问 Jaeger UI 的方式。

首先，我们需要为 Jaeger 创建一个命名空间。我们可以通过`kubectl create namespace`命令获取它：

```
kubectl create namespace observability
```

现在我们的命名空间已创建，我们需要创建一些 Jaeger 和操作员将使用的**CRDs**。我们将在我们的 Kubernetes 扩展章节中深入讨论 CRDs，但现在，把它们看作是一种利用 Kubernetes API 来构建应用程序自定义功能的方式。使用以下步骤，让我们安装 Jaeger：

1.  要创建 Jaeger CRDs，请运行以下命令：

```
kubectl create -f https://raw.githubusercontent.com/jaegertracing/jaeger-operator/master/deploy/crds/jaegertracing.io_jaegers_crd.yaml
```

创建了我们的 CRDs 后，操作员需要创建一些角色和绑定以便进行工作。

1.  我们希望 Jaeger 在我们的集群中拥有全局权限，因此我们将创建一些可选的 ClusterRoles 和 ClusterRoleBindings。为了实现这一点，我们运行以下命令：

```
kubectl create -n observability -f https://raw.githubusercontent.com/jaegertracing/jaeger-operator/master/deploy/service_account.yaml
kubectl create -n observability -f https://raw.githubusercontent.com/jaegertracing/jaeger-operator/master/deploy/role.yaml
kubectl create -n observability -f https://raw.githubusercontent.com/jaegertracing/jaeger-operator/master/deploy/role_binding.yaml
kubectl create -f https://raw.githubusercontent.com/jaegertracing/jaeger-operator/master/deploy/cluster_role.yaml
kubectl create -f https://raw.githubusercontent.com/jaegertracing/jaeger-operator/master/deploy/cluster_role_binding.yaml
```

1.  现在，我们终于拥有了操作员工作所需的所有要素。让我们用最后一个`kubectl`命令安装操作员：

```
kubectl create -n observability -f https://raw.githubusercontent.com/jaegertracing/jaeger-operator/master/deploy/operator.yaml
```

1.  最后，使用以下命令检查操作员是否正在运行：

```
kubectl get deploy -n observability
```

如果操作员正常运行，您将看到类似以下输出，部署中将有一个可用的 Pod：

![图 9.20 - Jaeger Operator Pod 输出](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cld-ntv-k8s/img/B14790_09_020_new.jpg)

图 9.20 - Jaeger Operator Pod 输出

我们现在已经启动并运行了我们的 Jaeger Operator - 但是 Jaeger 本身并没有在运行。为什么会这样？Jaeger 是一个非常复杂的系统，可以以不同的配置运行，操作员使得部署这些配置变得更加容易。

Jaeger Operator 使用一个名为`Jaeger`的 CRD 来读取您的 Jaeger 实例的配置，此时操作员将在 Kubernetes 上部署所有必要的 Pod 和其他资源。

Jaeger 可以以三种主要配置运行：*AllInOne*，*Production*和*Streaming*。对这些配置的全面讨论超出了本书的范围（请查看之前分享的 Jaeger 文档链接），但我们将使用 AllInOne 配置。这个配置将 Jaeger UI，Collector，Agent 和 Ingestor 组合成一个单独的 Pod，不包括任何持久存储。这非常适合演示目的 - 要查看生产就绪的配置，请查看 Jaeger 文档。

为了创建我们的 Jaeger 部署，我们需要告诉 Jaeger Operator 我们选择的配置。我们使用之前创建的 CRD - Jaeger CRD 来做到这一点。为此创建一个新文件：

Jaeger-allinone.yaml

```
apiVersion: jaegertracing.io/v1
kind: Jaeger
metadata:
  name: all-in-one
  namespace: observability
spec:
  strategy: allInOne
```

我们只是使用了可能的 Jaeger 类型配置的一个小子集 - 再次查看完整的文档以了解全部情况。

现在，我们可以通过运行以下命令来创建我们的 Jaeger 实例：

```
Kubectl apply -f jaeger-allinone.yaml
```

这个命令创建了我们之前安装的 Jaeger CRD 的一个实例。此时，Jaeger Operator 应该意识到已经创建了 CRD。不到一分钟，我们的实际 Jaeger Pod 应该正在运行。我们可以通过以下命令列出 observability 命名空间中的所有 Pod 来检查：

```
Kubectl get po -n observability
```

作为输出，您应该看到为我们的全功能实例新创建的 Jaeger Pod：

```
NAME                         READY   STATUS    RESTARTS   AGE
all-in-one-12t6bc95sr-aog4s  1/1     Running   0          5m
```

当我们的集群上也运行有 Ingress 控制器时，Jaeger Operator 会创建一个 Ingress 记录。这意味着我们可以简单地使用 kubectl 列出我们的 Ingress 条目，以查看如何访问 Jaeger UI。

您可以使用这个命令列出 Ingress：

```
Kubectl get ingress -n observability
```

输出应该显示您的 Jaeger UI 的新 Ingress，如下所示：

![图 9.21 - Jaeger UI 服务输出](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cld-ntv-k8s/img/B14790_09_021_new.jpg)

图 9.21 - Jaeger UI 服务输出

现在，您可以导航到集群 Ingress 记录中列出的地址，查看 Jaeger UI。它应该看起来像下面这样：

![图 9.22 – Jaeger UI](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cld-ntv-k8s/img/B14790_09_022_new.jpg)

图 9.22 – Jaeger UI

如您所见，Jaeger UI 非常简单。顶部有三个标签-**搜索**、**比较**和**系统架构**。我们将专注于**搜索**标签，但是要了解其他两个标签的更多信息，请查看 Jaeger 文档[`www.jaegertracing.io`](https://www.jaegertracing.io)。

Jaeger **搜索** 页面允许我们根据许多输入搜索跟踪。我们可以根据跟踪中包含的服务来搜索，也可以根据标签、持续时间等进行搜索。然而，现在我们的 Jaeger 系统中什么都没有。

原因是，即使我们已经启动并运行了 Jaeger，我们的应用程序仍然需要配置为将跟踪发送到 Jaeger。这通常需要在代码或框架级别完成，超出了本书的范围。如果您想尝试 Jaeger 的跟踪功能，可以安装一个示例应用程序-请参阅 Jaeger 文档页面[`www.jaegertracing.io/docs/1.18/getting-started/#sample-app-hotrod`](https://www.jaegertracing.io/docs/1.18/getting-started/#sample-app-hotrod)。

通过服务将跟踪发送到 Jaeger，可以查看跟踪。Jaeger 中的跟踪如下所示。为了便于阅读，我们裁剪了跟踪的后面部分，但这应该可以让您对跟踪的外观有一个很好的想法：

![图 9.23 – Jaeger 中的跟踪视图](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cld-ntv-k8s/img/B14790_09_023_new.jpg)

图 9.23 – Jaeger 中的跟踪视图

如您所见，Jaeger UI 视图将服务跟踪分成组成部分。每个服务之间的调用，以及服务内部的任何特定调用，在跟踪中都有自己的行。您看到的水平条形图从左到右移动，每个跟踪中的单独调用都有自己的行。在这个跟踪中，您可以看到我们有 HTTP 调用、SQL 调用，以及一些 Redis 语句。

您应该能够看到 Jaeger 和一般跟踪如何帮助开发人员理清服务之间的网络调用，并帮助找到瓶颈所在。

通过对 Jaeger 的回顾，我们对可观察性桶中的每个问题都有了一个完全开源的解决方案。然而，这并不意味着没有商业解决方案有用的情况-在许多情况下是有用的。

## 第三方工具

除了许多开源库之外，还有许多商业产品可用于 Kubernetes 上的指标、日志和警报。其中一些可能比开源选项更强大。

通常，大多数指标和日志工具都需要您在集群上配置资源，以将指标和日志转发到您选择的服务。在本章中我们使用的示例中，这些服务在集群中运行，尽管在商业产品中，这些通常可以是单独的 SaaS 应用程序，您可以登录分析日志并查看指标。例如，在本章中我们配置的 EFK 堆栈中，您可以支付 Elastic 提供的托管解决方案，其中解决方案的 Elasticsearch 和 Kibana 部分将托管在 Elastic 的基础设施上，从而降低了解决方案的复杂性。此外，还有许多其他解决方案，包括 Sumo Logic、Logz.io、New Relic、DataDog 和 AppDynamics 等供应商提供的解决方案。

对于生产环境，通常会使用单独的计算资源（可以是单独的集群、服务或 SaaS 工具）来执行日志和指标分析。这确保了运行实际软件的集群可以专门用于应用程序，并且任何昂贵的日志搜索或查询功能可以单独处理。这也意味着，如果我们的应用程序集群崩溃，我们仍然可以查看日志和指标，直到故障发生的时刻。

# 总结

在本章中，我们学习了关于 Kubernetes 上的可观察性。我们首先了解了可观察性的四个主要原则：指标、日志、跟踪和警报。然后我们发现了 Kubernetes 本身提供的可观察性工具，包括它如何管理日志和资源指标，以及如何部署 Kubernetes 仪表板。最后，我们学习了如何实施和使用一些关键的开源工具，为这四个支柱提供可视化、搜索和警报。这些知识将帮助您为未来的 Kubernetes 集群构建健壮的可观察性基础设施，并帮助您决定在集群中观察什么最重要。

在下一章中，我们将运用我们在 Kubernetes 上学到的可观察性知识来帮助我们排除应用程序故障。

# 问题

1.  解释指标和日志之间的区别。

1.  为什么要使用 Grafana 而不是简单地使用 Prometheus UI？

1.  在生产环境中运行 EFK 堆栈（以尽量减少生产应用集群的计算负载），堆栈的哪些部分会在生产应用集群上运行？哪些部分会在集群外运行？

# 进一步阅读

+   Kibana Timelion 的深度审查：[`www.elastic.co/guide/en/kibana/7.10/timelion-tutorial-create-time-series-visualizations.html`](https://www.elastic.co/guide/en/kibana/7.10/timelion-tutorial-create-time-series-visualizations.html)


# 第十章：排除故障的 Kubernetes

本章将审查有效排除 Kubernetes 集群和运行在其中的应用程序的最佳实践方法。这包括讨论常见的 Kubernetes 问题，以及如何分别调试主节点和工作节点。常见的 Kubernetes 问题将以案例研究的形式进行讨论和教学，分为集群问题和应用程序问题。

我们将首先讨论一些常见的 Kubernetes 故障模式，然后再讨论如何最好地排除集群和应用程序的故障。

在本章中，我们将涵盖以下主题：

+   理解分布式应用的故障模式

+   排除故障的 Kubernetes 集群

+   在 Kubernetes 上排除故障

# 技术要求

为了运行本章中详细介绍的命令，您需要一台支持`kubectl`命令行工具的计算机，以及一个正常运行的 Kubernetes 集群。请参阅*第一章*，*与 Kubernetes 通信*，了解快速启动和运行 Kubernetes 的几种方法，以及如何安装`kubectl`工具的说明。

本章中使用的代码可以在书籍的 GitHub 存储库中找到，网址为[`github.com/PacktPublishing/Cloud-Native-with-Kubernetes/tree/master/Chapter10`](https://github.com/PacktPublishing/Cloud-Native-with-Kubernetes/tree/master/Chapter10)。

# 理解分布式应用的故障模式

默认情况下，Kubernetes 组件（以及在 Kubernetes 上运行的应用程序）是分布式的，如果它们运行多个副本。这可能导致一些有趣的故障模式，这些故障模式可能很难调试。

因此，如果应用程序是无状态的，它们在 Kubernetes 上就不太容易失败-在这种情况下，状态被卸载到在 Kubernetes 之外运行的缓存或数据库中。Kubernetes 的原语，如 StatefulSets 和 PersistentVolumes，可以使在 Kubernetes 上运行有状态的应用程序变得更加容易-并且随着每个版本的发布，在 Kubernetes 上运行有状态的应用程序的体验也在不断改善。然而，决定在 Kubernetes 上运行完全有状态的应用程序会引入复杂性，因此也会增加失败的可能性。

分布式应用程序的故障可能由许多不同的因素引起。诸如网络可靠性和带宽限制等简单事物可能会导致重大问题。这些问题如此多样化，以至于*Sun Microsystems*的*Peter Deutsch*帮助撰写了*分布式计算的谬论*（连同*James Gosling*一起添加了第八点），这些谬论是关于分布式应用程序失败的共识因素。在论文*解释分布式计算的谬论*中，*Arnon Rotem-Gal-Oz*讨论了这些谬论的来源。

这些谬论按照数字顺序如下：

1.  网络是可靠的。

1.  延迟为零。

1.  带宽是无限的。

1.  网络是安全的。

1.  拓扑结构不会改变。

1.  只有一个管理员。

1.  传输成本为零。

1.  网络是同质的。

Kubernetes 在设计和开发时考虑了这些谬论，因此更具有容忍性。它还有助于解决在 Kubernetes 上运行的应用程序的这些问题-但并非完美。因此，当您的应用程序在 Kubernetes 上进行容器化并运行时，很可能会在面对这些问题时出现问题。每个谬论，当假设为不真实并推导到其逻辑结论时，都可能在分布式应用程序中引入故障模式。让我们逐个讨论 Kubernetes 和在 Kubernetes 上运行的应用程序的每个谬论。

## 网络是可靠的。

在多个逻辑机器上运行的应用程序必须通过互联网进行通信-因此，网络中的任何可靠性问题都可能引入问题。特别是在 Kubernetes 上，控制平面本身可以在高度可用的设置中进行分布（这意味着具有多个主节点的设置-请参见*第一章*，*与 Kubernetes 通信*），这意味着故障模式可能会在控制器级别引入。如果网络不可靠，那么 kubelet 可能无法与控制平面进行通信，从而导致 Pod 放置问题。

同样，控制平面的节点可能无法彼此通信-尽管`etcd`当然是使用一致性协议构建的，可以容忍通信故障。

最后，工作节点可能无法彼此通信-在微服务场景中，这可能会根据 Pod 的放置而引起问题。在某些情况下，工作节点可能都能够与控制平面通信，但仍然无法彼此通信，这可能会导致 Kubernetes 叠加网络出现问题。

与一般的不可靠性一样，延迟也可能引起许多相同的问题。

## 延迟是零

如果网络延迟显着，许多与网络不可靠性相同的故障也会适用。例如，kubelet 和控制平面之间的调用可能会失败，导致`etcd`中出现不准确的时期，因为控制平面可能无法联系 kubelet-或者正确更新`etcd`。同样，如果运行在工作节点上的应用程序之间的请求丢失，否则如果这些应用程序在同一节点上共存，则可以完美运行。

## 带宽是无限的

带宽限制可能会暴露与前两个谬论类似的问题。Kubernetes 目前没有完全支持的方法来基于带宽订阅来放置 Pod。这意味着达到网络带宽限制的节点仍然可以安排新的 Pod，导致请求的失败率和延迟问题增加。已经有要求将此作为核心 Kubernetes 调度功能添加的请求（基本上，一种根据节点带宽消耗进行调度的方法，就像 CPU 和内存一样），但目前，解决方案大多受限于容器网络接口（CNI）插件。

重要提示

举例来说，CNI 带宽插件支持在 Pod 级别进行流量整形-请参阅[`kubernetes.io/docs/concepts/extend-kubernetes/compute-storage-net/network-plugins/#support-traffic-shaping`](https://kubernetes.io/docs/concepts/extend-kubernetes/compute-storage-net/network-plugins/#support-traffic-shaping)。

第三方 Kubernetes 网络实现也可能提供围绕带宽的附加功能-并且许多与 CNI 带宽插件兼容。

## 网络是安全的

网络安全的影响远不止于 Kubernetes——因为任何不安全的网络都可能遭受各种攻击。攻击者可能能够获得对 Kubernetes 集群中的主节点或工作节点的 SSH 访问权限，这可能会造成重大破坏。由于 Kubernetes 的许多功能都是通过网络而不是在单台机器上完成的，因此在攻击情况下对网络的访问会变得更加棘手。

## 拓扑结构不会改变

这种谬误在 Kubernetes 的背景下尤为重要，因为不仅可以通过添加和移除新节点来改变元网络拓扑结构，覆盖网络拓扑结构也会直接受到 Kubernetes 控制平面和 CNI 的影响。

因此，一个应用程序在某一时刻在一个逻辑位置运行，可能在网络中的完全不同位置运行。因此，使用 Pod IP 来识别逻辑应用程序是一个不好的主意——这是服务抽象的一个目的（参见*第五章*，*服务和入口*——*与外部世界通信*）。任何不考虑集群内部拓扑结构（至少涉及 IP）的应用程序可能会出现问题。例如，将应用程序路由到特定的 Pod IP 只能在该 Pod 发生变化之前起作用。如果该 Pod 关闭，控制它的部署（例如）将启动一个新的 Pod 来替代它，但 IP 将完全不同。集群 DNS（以及由此衍生的服务）为在集群中的应用程序之间进行请求提供了更好的方式，除非您的应用程序具有动态调整到集群变化（如 Pod 位置）的能力。

## 只有一个管理员

在基础网络中，多个管理员和冲突的规则可能会导致问题，多个 Kubernetes 管理员还可能通过更改资源配置（例如 Pod 资源限制）而引发进一步的问题，导致意外行为。使用 Kubernetes 的**基于角色的访问控制**（**RBAC**）功能可以通过为 Kubernetes 用户提供他们所需的权限（例如只读权限）来解决这个问题。

## 运输成本为零

这种谬误有两种常见的解释方式。首先，传输的延迟成本为零 - 这显然是不真实的，因为数据在电线上传输的速度并不是无限的，而且更低级的网络问题会增加延迟。这与“延迟为零”谬误产生的影响本质上是相同的。

其次，这个声明可以被解释为创建和操作网络传输的成本为零 - 就像零美元和零美分一样。虽然这也是显然不真实的（只需看看您的云服务提供商的数据传输费用就可以证明），但这并不特别对应于 Kubernetes 上的应用程序故障排查，所以我们将专注于第一种解释。

## 网络是同质的

这个最后的谬误与 Kubernetes 的组件关系不大，而与在 Kubernetes 上运行的应用程序有更多关系。然而，事实是，今天的环境中操作的开发人员都清楚地知道，应用程序网络可能在不同的应用程序中有不同的实现 - 从 HTTP 1 和 2 到诸如 *gRPC* 的协议。

现在我们已经回顾了一些 Kubernetes 应用失败的主要原因，我们可以深入研究排查 Kubernetes 和在 Kubernetes 上运行的应用程序的实际过程。

# 排查 Kubernetes 集群

由于 Kubernetes 是一个分布式系统，旨在容忍应用程序运行的故障，大多数（但不是全部）问题往往集中在控制平面和 API 上。在大多数情况下，工作节点的故障只会导致 Pod 被重新调度到另一个节点 - 尽管复合因素可能会引入问题。

为了演示常见的 Kubernetes 集群问题场景，我们将使用案例研究方法。这应该为您提供调查真实世界集群问题所需的所有工具。我们的第一个案例研究集中在 API 服务器本身的故障上。

重要提示

在本教程中，我们将假设一个自管理的集群。托管的 Kubernetes 服务，如 EKS、AKS 和 GKE 通常会消除一些故障域（例如通过自动缩放和管理主节点）。一个好的规则是首先检查您的托管服务文档，因为任何问题可能是特定于实现的。

## 案例研究 - Kubernetes Pod 放置失败

让我们来设定场景。您的集群正在运行，但是您遇到了 Pod 调度的问题。Pods 一直停留在 `Pending` 状态，无限期地。让我们用以下命令确认一下：

```
kubectl get pods
```

命令的输出如下：

```
NAME                              READY     STATUS    RESTARTS   AGE
app-1-pod-2821252345-tj8ks        0/1       Pending   0          2d
app-1-pod-2821252345-9fj2k        0/1       Pending   0          2d
app-1-pod-2821252345-06hdj        0/1       Pending   0          2d
```

正如我们所看到的，我们的 Pod 都没有在运行。此外，我们正在运行应用程序的三个副本，但没有一个被调度。下一个很好的步骤是检查节点状态，看看是否有任何问题。运行以下命令以获取输出：

```
kubectl get nodes
```

我们得到以下输出：

```
  NAME           STATUS     ROLES    AGE    VERSION
  node-01        NotReady   <none>   5m     v1.15.6
```

这个输出给了我们一些很好的信息 - 我们只有一个工作节点，并且它无法用于调度。当 `get` 命令没有给我们足够的信息时，`describe` 通常是一个很好的下一步。

让我们运行 `kubectl describe node node-01` 并检查 `conditions` 键。我们已经删除了一列，以便将所有内容整齐地显示在页面上，但最重要的列都在那里：

![图 10.1 - 描述节点条件输出](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cld-ntv-k8s/img/B14790_10_001.jpg)

图 10.1 - 描述节点条件输出

我们在这里有一个有趣的分裂：`MemoryPressure` 和 `DiskPressure` 都很好，而 `OutOfDisk` 和 `Ready` 条件的状态是未知的，消息是 `kubelet stopped posting node status`。乍一看，这似乎是荒谬的 - `MemoryPressure` 和 `DiskPressure` 怎么可能正常，而 kubelet 却停止工作了呢？

重要的部分在 `LastTransitionTime` 列中。kubelet 最近的内存和磁盘特定通信发送了积极的状态。然后，在稍后的时间，kubelet 停止发布其节点状态，导致 `OutOfDisk` 和 `Ready` 条件的状态为 `Unknown`。

在这一点上，我们可以肯定我们的节点是问题所在 - kubelet 不再将节点状态发送到控制平面。然而，我们不知道为什么会发生这种情况。可能是网络错误，机器本身的问题，或者更具体的问题。我们需要进一步挖掘才能弄清楚。

在这里一个很好的下一步是接近我们的故障节点，因为我们可以合理地假设它遇到了某种问题。如果您可以访问 `node-01` VM 或机器，现在是 SSH 进入的好时机。一旦我们进入机器，让我们进一步进行故障排除。

首先，让我们检查节点是否可以通过网络访问控制平面。如果不能，这显然是 kubelet 无法发布状态的明显原因。假设我们的集群控制平面（例如，本地负载均衡器）位于`10.231.0.1`，为了检查我们的节点是否可以访问 Kubernetes API 服务器，我们可以像下面这样 ping 控制平面：

```
ping 10.231.0.1   
```

重要提示

为了找到控制平面的 IP 或 DNS，请检查您的集群配置。在 AWS Elastic Kubernetes Service 或 Azure AKS 等托管的 Kubernetes 服务中，这可能可以在控制台中查看。例如，如果您使用 kubeadm 自己引导了集群，那么这是您在安装过程中提供的值之一。

让我们来检查结果：

```
Reply from 10.231.0.1: bytes=1500 time=28ms TTL=54
Reply from 10.231.0.1: bytes=1500 time=26ms TTL=54
Reply from 10.231.0.1: bytes=1500 time=27ms TTL=54
```

这证实了 - 我们的节点确实可以与 Kubernetes 控制平面通信。因此，网络不是问题。接下来，让我们检查实际的 kubelet 服务。节点本身似乎是正常运行的，网络也正常，所以逻辑上，kubelet 是下一个要检查的东西。

Kubernetes 组件在 Linux 节点上作为系统服务运行。

重要提示

在 Windows 节点上，故障排除说明会略有不同 - 请参阅 Kubernetes 文档以获取更多信息（[`kubernetes.io/docs/setup/production-environment/windows/intro-windows-in-kubernetes/`](https://kubernetes.io/docs/setup/production-environment/windows/intro-windows-in-kubernetes/)）。

为了找出我们的`kubelet`服务的状态，我们可以运行以下命令：

```
systemctl status kubelet -l 
```

这给我们以下输出：

```
 • kubelet.service - kubelet: The Kubernetes Node Agent
   Loaded: loaded (/lib/systemd/system/kubelet.service; enabled)
  Drop-In: /etc/systemd/system/kubelet.service.d
           └─10-kubeadm.conf
   Active: activating (auto-restart) (Result: exit-code) since Fri 2020-05-22 05:44:25 UTC; 3s ago
     Docs: http://kubernetes.io/docs/
  Process: 32315 ExecStart=/usr/bin/kubelet $KUBELET_KUBECONFIG_ARGS $KUBELET_SYSTEM_PODS_ARGS $KUBELET_NETWORK_ARGS $KUBELET_DNS_ARGS $KUBELET_AUTHZ_ARGS $KUBELET_CADVISOR_ARGS $KUBELET_CERTIFICATE_ARGS $KUBELET_EXTRA_ARGS (code=exited, status=1/FAILURE)
 Main PID: 32315 (code=exited, status=1/FAILURE)
```

看起来我们的 kubelet 目前没有运行 - 它以失败退出。这解释了我们所看到的集群状态和 Pod 问题。

实际上修复问题，我们可以首先尝试使用以下命令重新启动`kubelet`：

```
systemctl start kubelet
```

现在，让我们使用我们的状态命令重新检查`kubelet`的状态：

```
 • kubelet.service - kubelet: The Kubernetes Node Agent
   Loaded: loaded (/lib/systemd/system/kubelet.service; enabled)
  Drop-In: /etc/systemd/system/kubelet.service.d
           └─10-kubeadm.conf
   Active: activating (auto-restart) (Result: exit-code) since Fri 2020-05-22 06:13:48 UTC; 10s ago
     Docs: http://kubernetes.io/docs/
  Process: 32007 ExecStart=/usr/bin/kubelet $KUBELET_KUBECONFIG_ARGS $KUBELET_SYSTEM_PODS_ARGS $KUBELET_NETWORK_ARGS $KUBELET_DNS_ARGS $KUBELET_AUTHZ_ARGS $KUBELET_CADVISOR_ARGS $KUBELET_CERTIFICATE_ARGS $KUBELET_EXTRA_ARGS (code=exited, status=1/FAILURE)
 Main PID: 32007 (code=exited, status=1/FAILURE)
```

看起来`kubelet`又失败了。我们需要获取一些关于失败模式的额外信息，以便找出发生了什么。

让我们使用`journalctl`命令查看是否有相关的日志：

```
sudo journalctl -u kubelet.service | grep "failed"
```

输出应该显示`kubelet`服务的日志，其中发生了故障：

```
May 22 04:19:16 nixos kubelet[1391]: F0522 04:19:16.83719    1287 server.go:262] failed to run Kubelet: Running with swap on is not supported, please disable swap! or set --fail-swap-on flag to false. /proc/swaps contained: [Filename                                Type                Size        Used        Priority /dev/sda1                               partition        6198732        0        -1]
```

看起来我们已经找到了原因-Kubernetes 默认不支持在 Linux 机器上运行时将`swap`设置为`on`。我们在这里的唯一选择要么是禁用`swap`，要么是使用设置为`false`的`--fail-swap-on`标志重新启动`kubelet`。

在我们的情况下，我们将使用以下命令更改`swap`设置：

```
sudo swapoff -a
```

现在，重新启动`kubelet`服务：

```
sudo systemctl restart kubelet
```

最后，让我们检查一下我们的修复是否奏效。使用以下命令检查节点：

```
kubectl get nodes 
```

这应该显示类似于以下内容的输出：

```
  NAME           STATUS     ROLES    AGE    VERSION
  node-01        Ready      <none>   54m    v1.15.6
```

我们的节点最终发布了`Ready`状态！

让我们使用以下命令检查我们的 Pod：

```
kubectl get pods
```

这应该显示如下输出：

```
NAME                              READY     STATUS    RESTARTS   AGE
app-1-pod-2821252345-tj8ks        1/1       Running   0          1m
app-1-pod-2821252345-9fj2k        1/1       Running   0          1m
app-1-pod-2821252345-06hdj        1/1       Running   0          1m
```

成功！我们的集群健康，我们的 Pod 正在运行。

接下来，让我们看看在解决了任何集群问题后如何排除 Kubernetes 上的应用程序故障。

# 在 Kubernetes 上排除应用程序故障

一个完全运行良好的 Kubernetes 集群可能仍然存在需要调试的应用程序问题。这可能是由于应用程序本身的错误，也可能是由于组成应用程序的 Kubernetes 资源的错误配置。与排除集群故障一样，我们将通过使用案例研究来深入了解这些概念。

## 案例研究 1-服务无响应

我们将把这一部分分解为 Kubernetes 堆栈各个级别的故障排除，从更高级别的组件开始，然后深入到 Pod 和容器调试。

假设我们已经配置我们的应用程序`app-1`通过`NodePort`服务响应端口`32688`的请求。该应用程序监听端口`80`。

我们可以尝试通过在我们的节点之一上使用`curl`请求来访问我们的应用程序。命令将如下所示：

```
curl http://10.213.2.1:32688
```

如果 curl 命令失败，输出将如下所示：

```
curl: (7) Failed to connect to 10.231.2.1 port 32688: Connection refused
```

此时，我们的`NodePort`服务没有将请求路由到任何 Pod。按照我们典型的调试路径，让我们首先查看使用以下命令在集群中运行的哪些资源：

```
kubectl get services
```

添加`-o`宽标志以查看更多信息。接下来，运行以下命令：

```
kubectl get services -o wide 
```

这给了我们以下输出：

```
NAME TYPE CLUSTER-IP EXTERNAL-IP PORT(S) AGE SELECTOR 
app-1-svc NodePort 10.101.212.57 <none> 80:32688/TCP 3m01s app=app-1
```

很明显，我们的服务存在一个正确的节点端口-但是我们的请求没有被路由到 Pod，这是从失败的 curl 命令中显而易见的。

要查看我们的服务设置了哪些路由，让我们使用`get endpoints`命令。这将列出服务配置的 Pod IP（如果有的话）。

```
kubectl get endpoints app-1-svc
```

让我们检查命令的结果输出：

```
NAME        ENDPOINTS
app-1-svc   <none>
```

嗯，这里肯定有问题。

我们的服务没有指向任何 Pod。这很可能意味着没有任何与我们的服务选择器匹配的 Pod 可用。这可能是因为根本没有可用的 Pod - 或者因为这些 Pod 不正确地匹配了服务选择器。

要检查我们的服务选择器，让我们沿着调试路径迈出下一步，并使用以下命令：

```
kubectl describe service app-1-svc  
```

这给我们一个类似以下的输出：

```
Name:                   app-1-svc
Namespace:              default
Labels:                 app=app-11
Annotations:            <none>
Selector:               app=app-11
Type:                   NodePort
IP:                     10.57.0.15
Port:                   <unset> 80/TCP
TargetPort:             80/TCP
NodePort:               <unset> 32688/TCP
Endpoints:              <none>
Session Affinity:       None
Events:                 <none>
```

正如您所看到的，我们的服务配置为与我们的应用程序上的正确端口进行通信。但是，选择器正在寻找与标签`app = app-11`匹配的 Pod。由于我们知道我们的应用程序名称为`app-1`，这可能是我们问题的原因。

让我们编辑我们的服务，以寻找正确的 Pod 标签`app-1`，再次运行另一个`describe`命令以确保：

```
kubectl describe service app-1-svc
```

这会产生以下输出：

```
Name:                   app-1-svc
Namespace:              default
Labels:                 app=app-1
Annotations:            <none>
Selector:               app=app-1
Type:                   NodePort
IP:                     10.57.0.15
Port:                   <unset> 80/TCP
TargetPort:             80/TCP
NodePort:               <unset> 32688/TCP
Endpoints:              <none>
Session Affinity:       None
Events:                 <none>
```

现在，您可以在输出中看到我们的服务正在寻找正确的 Pod 选择器，但我们仍然没有任何端点。让我们使用以下命令来查看我们的 Pod 的情况：

```
kubectl get pods
```

这显示了以下输出：

```
NAME                              READY     STATUS    RESTARTS   AGE
app-1-pod-2821252345-tj8ks        0/1       Pending   0          -
app-1-pod-2821252345-9fj2k        0/1       Pending   0          -
app-1-pod-2821252345-06hdj        0/1       Pending   0          -
```

我们的 Pod 仍在等待调度。这解释了为什么即使有正确的选择器，我们的服务也无法正常运行。为了更细致地了解为什么我们的 Pod 没有被调度，让我们使用`describe`命令：

```
kubectl describe pod app-1-pod-2821252345-tj8ks
```

以下是输出。让我们专注于“事件”部分：

![图 10.2 - 描述 Pod 事件输出](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cld-ntv-k8s/img/B14790_10_002.jpg)

图 10.2 - 描述 Pod 事件输出

从“事件”部分来看，似乎我们的 Pod 由于容器镜像拉取失败而无法被调度。这可能有很多原因 - 例如，我们的集群可能没有必要的身份验证机制来从私有仓库拉取，但这会出现不同的错误消息。

从上下文和“事件”输出来看，我们可能可以假设问题在于我们的 Pod 定义正在寻找一个名为`myappimage:lates`的容器，而不是`myappimage:latest`。

让我们使用正确的镜像名称更新我们的部署规范并进行更新。

使用以下命令来确认：

```
kubectl get pods
```

输出看起来像这样：

```
NAME                              READY     STATUS    RESTARTS   AGE
app-1-pod-2821252345-152sf        1/1       Running   0          1m
app-1-pod-2821252345-9gg9s        1/1       Running   0          1m
app-1-pod-2821252345-pfo92        1/1       Running   0          1m
```

我们的 Pod 现在正在运行 - 让我们检查一下我们的服务是否已注册了正确的端点。使用以下命令来执行此操作：

```
kubectl describe services app-1-svc
```

输出应该是这样的：

```
Name:                   app-1-svc
Namespace:              default
Labels:                 app=app-1
Annotations:            <none>
Selector:               app=app-1
Type:                   NodePort
IP:                     10.57.0.15
Port:                   <unset> 80/TCP
TargetPort:             80/TCP
NodePort:               <unset> 32688/TCP
Endpoints:              10.214.1.3:80,10.214.2.3:80,10.214.4.2:80
Session Affinity:       None
Events:                 <none>
```

成功！我们的服务正确地指向了我们的应用程序 Pod。

在下一个案例研究中，我们将通过排除具有不正确启动参数的 Pod 来深入挖掘一些问题。

## 案例研究 2 - 错误的 Pod 启动命令

让我们假设我们的 Service 已经正确配置，我们的 Pods 正在运行并通过健康检查。然而，我们的 Pod 没有按照我们的预期响应请求。我们确信这不是 Kubernetes 的问题，而更多是应用程序或配置的问题。

我们的应用程序容器工作方式如下：它接受一个带有`color`标志的启动命令，并根据容器的`image`标签的`version number`变量组合起来，并将其回显给请求者。我们期望我们的应用程序返回`green 3`。

幸运的是，Kubernetes 为我们提供了一些很好的工具来调试应用程序，我们可以用这些工具来深入研究我们特定的容器。

首先，让我们使用以下命令`curl`应用程序，看看我们得到什么响应：

```
curl http://10.231.2.1:32688  
red 2
```

我们期望得到`green 3`，但得到了`red 2`，所以看起来输入和版本号变量出了问题。让我们先从前者开始。

像往常一样，我们首先用以下命令检查我们的 Pods：

```
kubectl get pods
```

输出应该如下所示：

```
NAME                              READY     STATUS    RESTARTS   AGE
app-1-pod-2821252345-152sf        1/1       Running   0          5m
app-1-pod-2821252345-9gg9s        1/1       Running   0          5m
app-1-pod-2821252345-pfo92        1/1       Running   0          5m
```

这个输出看起来很好。我们的应用程序似乎作为部署的一部分运行（因此也是 ReplicaSet） - 我们可以通过运行以下命令来确保：

```
kubectl get deployments
```

输出应该如下所示：

```
NAME          DESIRED   CURRENT   UP-TO-DATE   AVAILABLE   AGE
app-1-pod     3         3         3            3           5m
```

让我们更仔细地查看我们的部署，看看我们的 Pods 是如何配置的，使用以下命令：

```
kubectl describe deployment app-1-pod -o yaml
```

输出应该如下所示：

Broken-deployment-output.yaml

```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app-1-pod
spec:
  selector:
    matchLabels:
      app: app-1
  replicas: 3
  template:
    metadata:
      labels:
        app: app-1
    spec:
      containers:
      - name: app-1
        image: mycustomrepository/app-1:2
        command: [ "start", "-color", "red" ]
        ports:
        - containerPort: 80
```

让我们看看是否可以解决我们的问题，这实际上非常简单。我们使用了错误版本的应用程序，而且我们的启动命令也是错误的。在这种情况下，让我们假设我们没有一个包含我们部署规范的文件 - 所以让我们直接在原地编辑它。

让我们使用`kubectl edit deployment app-1-pod`，并编辑 Pod 规范如下：

fixed-deployment-output.yaml

```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app-1-pod
spec:
  selector:
    matchLabels:
      app: app-1
  replicas: 3
  template:
    metadata:
      labels:
        app: app-1
    spec:
      containers:
      - name: app-1
        image: mycustomrepository/app-1:3
        command: [ "start", "-color", "green" ]
        ports:
        - containerPort: 80
```

一旦部署保存，你应该开始看到你的新 Pods 启动。让我们通过以下命令再次检查：

```
 kubectl get pods
```

输出应该如下所示：

```
NAME                              READY     STATUS    RESTARTS   AGE
app-1-pod-2821252345-f928a        1/1       Running   0          1m
app-1-pod-2821252345-jjsa8        1/1       Running   0          1m
app-1-pod-2821252345-92jhd        1/1       Running   0          1m
```

最后 - 让我们发出一个`curl`请求来检查一切是否正常运行：

```
curl http://10.231.2.1:32688  
```

命令的输出如下：

```
green 3
```

成功！

## 案例研究 3 - Pod 应用程序日志故障

在上一章[*第九章*]（B14790_9_Final_PG_ePub.xhtml#_idTextAnchor212），*Kubernetes 上的可观测性*中，我们为我们的应用程序实现了可观测性，让我们看一个案例，这些工具确实非常有用。我们将使用手动的`kubectl`命令来进行这个案例研究 - 但要知道，通过聚合日志（例如，在我们的 EFK 堆栈实现中），我们可以使调试这个应用程序的过程变得更容易。

在这个案例研究中，我们再次部署了 Pod - 为了检查它，让我们运行以下命令：

```
kubectl get pods
```

命令的输出如下：

```
NAME              READY     STATUS    RESTARTS   AGE
app-2-ss-0        1/1       Running   0          10m
app-2-ss-1       1/1       Running   0          10m
app-2-ss-2       1/1       Running   0          10m
```

看起来，在这种情况下，我们使用的是 StatefulSet 而不是 Deployment - 这里的一个关键特征是从 0 开始递增的 Pod ID。

我们可以通过使用以下命令来确认这一点：

```
kubectl get statefulset
```

命令的输出如下：

```
NAME          DESIRED   CURRENT   UP-TO-DATE   AVAILABLE   AGE
app-2-ss      3         3         3            3           10m
```

让我们使用`kubectl get statefulset -o yaml app-2-ss`来更仔细地查看我们的 StatefulSet。通过使用`get`命令以及`-o yaml`，我们可以以与典型的 Kubernetes 资源 YAML 相同的格式获得我们的`describe`输出。

上述命令的输出如下。我们已经删除了 Pod 规范部分以使其更短：

statefulset-output.yaml

```
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: app-2-ss
spec:
  selector:
    matchLabels:
      app: app-2
  replicas: 3
  template:
    metadata:
      labels:
        app: app-2
```

我们知道我们的应用程序正在使用一个服务。让我们看看是哪一个！

运行 `kubectl get services -o wide`。输出应该类似于以下内容：

```
NAME TYPE CLUSTER-IP EXTERNAL-IP PORT(S) AGE SELECTOR 
app-2-svc NodePort 10.100.213.13 <none> 80:32714/TCP 3m01s app=app-2
```

很明显我们的服务叫做`app-2-svc`。让我们使用以下命令查看我们的确切服务定义：

```
kubectl describe services app-2-svc 
```

命令的输出如下：

```
Name:                   app-2-svc
Namespace:              default
Labels:                 app=app-2
Annotations:            <none>
Selector:               app=app-2
Type:                   NodePort
IP:                     10.57.0.12
Port:                   <unset> 80/TCP
TargetPort:             80/TCP
NodePort:               <unset> 32714/TCP
Endpoints:              10.214.1.1:80,10.214.2.3:80,10.214.4.4:80
Session Affinity:       None
Events:                 <none>
```

要确切地查看我们的应用程序对于给定输入返回的内容，我们可以在我们的`NodePort`服务上使用`curl`：

```
> curl http://10.231.2.1:32714?equation=1plus1
3
```

根据我们对应用程序的现有知识，我们会假设这个调用应该返回`2`而不是`3`。我们团队的应用程序开发人员已经要求我们调查任何日志输出，以帮助他们找出问题所在。

我们知道从之前的章节中，你可以使用`kubectl logs <pod name>`来调查日志输出。在我们的情况下，我们有三个应用程序的副本，所以我们可能无法在一次迭代中找到我们的日志。让我们随机选择一个 Pod，看看它是否是为我们提供服务的那个：

```
> kubectl logs app-2-ss-1
>
```

看起来这不是为我们提供服务的 Pod，因为我们的应用程序开发人员告诉我们，当向服务器发出`GET`请求时，应用程序肯定会记录到`stdout`。

我们可以使用联合命令从所有三个 Pod 中获取日志，而不是逐个检查另外两个 Pod。命令将如下：

```
> kubectl logs statefulset/app-2-ss
```

输出如下：

```
> Input = 1plus1
> Operator = plus
> First Number = 1
> Second Number = 2
```

这样就解决了问题 - 而且更重要的是，我们可以看到一些关于我们问题的很好的见解。

除了日志行读取`Second Number`之外，一切都如我们所期望的那样。我们的请求明显使用`1plus1`作为查询字符串，这将使第一个数字和第二个数字（由运算符值分隔）都等于一。

这将需要一些额外的挖掘。我们可以通过发送额外的请求并检查输出来对这个问题进行分类，以猜测发生了什么，但在这种情况下，最好只是获取对 Pod 的 bash 访问并弄清楚发生了什么。

首先，让我们检查一下我们的 Pod 规范，这是从前面的 StatefulSet YAML 中删除的。要查看完整的 StatefulSet 规范，请检查 GitHub 存储库：

Statefulset-output.yaml

```
spec:
  containers:
  - name: app-2
    image: mycustomrepository/app-2:latest
    volumeMounts:
    - name: scratch
      mountPath: /scratch
  - name: sidecar
    image: mycustomrepository/tracing-sidecar
  volumes:
  - name: scratch-volume
    emptyDir: {}
```

看起来我们的 Pod 正在挂载一个空卷作为临时磁盘。每个 Pod 中还有两个容器 - 一个用于应用程序跟踪的 sidecar，以及我们的应用程序本身。我们需要这些信息来使用`kubectl exec`命令`ssh`到其中一个 Pod（对于这个练习来说，无论选择哪一个都可以）。

我们可以使用以下命令来完成：

```
kubectl exec -it app-2-ss-1 app2 -- sh.  
```

这个命令应该给你一个 bash 终端作为输出：

```
> kubectl exec -it app-2-ss-1 app2 -- sh
# 
```

现在，使用我们刚创建的终端，我们应该能够调查我们的应用程序代码。在本教程中，我们使用了一个非常简化的 Node.js 应用程序。

让我们检查一下我们的 Pod 文件系统，看看我们使用以下命令在处理什么：

```
# ls
# app.js calculate.js scratch
```

看起来我们有两个 JavaScript 文件，以及我们之前提到的`scratch`文件夹。可以假设`app.js`包含引导和提供应用程序的逻辑，而`calculate.js`包含我们的控制器代码来进行计算。

我们可以通过打印`calculate.js`文件的内容来确认：

Broken-calculate.js

```
# cat calculate.js
export const calculate(first, second, operator)
{
  second++;
  if(operator === "plus")
  {
   return first + second;
  }
}
```

即使对 JavaScript 几乎一无所知，这里的问题也是非常明显的。代码在执行计算之前递增了`second`变量。

由于我们在 Pod 内部，并且正在使用非编译语言，我们实际上可以内联编辑这个文件！让我们使用`vi`（或任何文本编辑器）来纠正这个文件：

```
# vi calculate.js
```

并编辑文件如下所示：

fixed-calculate.js

```
export const calculate(first, second, operator)
{
  if(operator === "plus")
  {
   return first + second;
  }
}
```

现在，我们的代码应该正常运行。重要的是要说明，这个修复只是临时的。一旦我们的 Pod 关闭或被另一个 Pod 替换，它将恢复到最初包含在容器镜像中的代码。然而，这种模式确实允许我们尝试快速修复。

在使用`exit` bash 命令退出`exec`会话后，让我们再次尝试我们的 URL：

```
> curl http://10.231.2.1:32714?equation=1plus1
2
```

正如你所看到的，我们的热修复容器显示了正确的结果！现在，我们可以使用我们的修复以更加永久的方式更新我们的代码和 Docker 镜像。使用`exec`是一个很好的方法来排除故障和调试运行中的容器。

# 总结

在本章中，我们学习了如何在 Kubernetes 上调试应用程序。首先，我们介绍了分布式应用程序的一些常见故障模式。然后，我们学习了如何对 Kubernetes 组件的问题进行分类。最后，我们回顾了几种 Kubernetes 配置和应用程序调试的场景。在本章中学到的 Kubernetes 调试和故障排除技术将帮助你在处理任何 Kubernetes 集群和应用程序的问题时。

在下一章，*第十一章*，*Kubernetes 上的模板代码生成和 CI/CD*，我们将探讨一些用于模板化 Kubernetes 资源清单和与 Kubernetes 一起进行持续集成/持续部署的生态系统扩展。

# 问题

1.  分布式系统谬误“*拓扑结构不会改变*”如何适用于 Kubernetes 上的应用程序？

1.  Kubernetes 控制平面组件（和 kubelet）在操作系统级别是如何实现的？

1.  当 Pod 被卡在`Pending`状态时，你会如何调试问题？你的第一步会是什么？第二步呢？

# 进一步阅读

+   用于流量整形的 CNI 插件：[`kubernetes.io/docs/concepts/extend-kubernetes/compute-storage-net/network-plugins/#support-traffic-shaping`](https://kubernetes.io/docs/concepts/extend-kubernetes/compute-storage-net/network-plugins/#support-traffic-shaping)


# 第十一章：Kubernetes 上的模板代码生成和 CI/CD

本章讨论了一些更容易的方法，用于模板化和配置具有许多资源的大型 Kubernetes 部署。它还详细介绍了在 Kubernetes 上实施**持续集成**/**持续部署**（**CI**/**CD**）的多种方法，以及与每种可能方法相关的利弊。具体来说，我们谈论了集群内 CI/CD，其中一些或所有的 CI/CD 步骤在我们的 Kubernetes 集群中执行，以及集群外 CI/CD，其中所有步骤都在我们的集群之外进行。

本章的案例研究将包括从头开始创建 Helm 图表，以及对 Helm 图表的每个部分及其工作原理的解释。

首先，我们将介绍 Kubernetes 资源模板生成的概况，以及为什么应该使用模板生成工具。然后，我们将首先使用 AWS CodeBuild，然后使用 FluxCD 来实施 CI/CD 到 Kubernetes。

在本章中，我们将涵盖以下主题：

+   了解在 Kubernetes 上进行模板代码生成的选项

+   使用 Helm 和 Kustomize 在 Kubernetes 上实施模板

+   了解 Kubernetes 上的 CI/CD 范式-集群内和集群外

+   在 Kubernetes 上实施集群内和集群外的 CI/CD

# 技术要求

为了运行本章中详细介绍的命令，您需要一台支持`kubectl`命令行工具的计算机，以及一个可用的 Kubernetes 集群。请参考*第一章*，*与 Kubernetes 通信*，了解快速启动和运行 Kubernetes 的几种方法，以及如何安装 kubectl 工具的说明。此外，您还需要一台支持 Helm CLI 工具的机器，通常具有与 kubectl 相同的先决条件-有关详细信息，请查看 Helm 文档[`helm.sh/docs/intro/install/`](https://helm.sh/docs/intro/install/)。

本章中使用的代码可以在书籍的 GitHub 存储库中找到

[`github.com/PacktPublishing/Cloud-Native-with-Kubernetes/tree/master/Chapter11`](https://github.com/PacktPublishing/Cloud-Native-with-Kubernetes/tree/master/Chapter11)。

# 了解在 Kubernetes 上进行模板代码生成的选项

正如在*第一章*中讨论的那样，*与 Kubernetes 通信*，Kubernetes 最大的优势之一是其 API 可以通过声明性资源文件进行通信。这使我们能够运行诸如`kubectl apply`之类的命令，并确保控制平面确保集群中运行的任何资源与我们的 YAML 或 JSON 文件匹配。

然而，这种能力引入了一些难以控制的因素。由于我们希望将所有工作负载声明在配置文件中，任何大型或复杂的应用程序，特别是如果它们包含许多微服务，可能会导致大量的配置文件编写和维护。

这个问题在多个环境下会更加复杂。假设我们需要开发、暂存、UAT 和生产环境，这将需要每个 Kubernetes 资源四个单独的 YAML 文件，假设我们想要保持每个文件一个资源的清晰度。

解决这些问题的一种方法是使用支持变量的模板系统，允许单个模板文件适用于多个应用程序或多个环境，通过注入不同的变量集。

有几种受社区支持的流行开源选项可用于此目的。在本书中，我们将重点关注其中两种最受欢迎的选项。

+   Helm

+   Kustomize

有许多其他选项可供选择，包括 Kapitan、Ksonnet、Jsonnet 等，但本书不在讨论范围之内。让我们先来回顾一下 Helm，它在很多方面都是最受欢迎的模板工具。

## Helm

Helm 实际上扮演了模板/代码生成工具和 CI/CD 工具的双重角色。它允许您创建基于 YAML 的模板，可以使用变量进行填充，从而实现跨应用程序和环境的代码和模板重用。它还配备了一个 Helm CLI 工具，可以根据模板本身来推出应用程序的更改。

因此，你可能会在 Kubernetes 生态系统中到处看到 Helm 作为安装工具或应用程序的默认方式。在本章中，我们将使用 Helm 来完成它的两个目的。

现在，让我们转向 Kustomize，它与 Helm 有很大不同。

## Kustomize

与 Helm 不同，Kustomize 得到了 Kubernetes 项目的官方支持，并且支持直接集成到`kubectl`中。与 Helm 不同，Kustomize 使用原始的 YAML 而不是变量，并建议使用*fork and patch*工作流，在这个工作流中，YAML 的部分根据所选择的补丁被替换为新的 YAML。

既然我们对这些工具的区别有了基本的了解，我们可以在实践中使用它们。

# 使用 Helm 和 Kustomize 在 Kubernetes 上实现模板

既然我们知道了我们的选择，我们可以用一个示例应用程序来实现它们中的每一个。这将使我们能够了解每个工具处理变量和模板化过程的具体细节。让我们从 Helm 开始。

## 使用 Helm 与 Kubernetes

如前所述，Helm 是一个开源项目，它使得在 Kubernetes 上模板化和部署应用程序变得容易。在本书的目的上，我们将专注于最新版本（写作时），即 Helm V3。之前的版本 Helm V2 有更多的移动部分，包括一个称为*Tiller*的控制器，它会在集群上运行。Helm V3 被简化了，只包含 Helm CLI 工具。然而，它在集群上使用自定义资源定义来跟踪发布，我们很快就会看到。

让我们从安装 Helm 开始。

### 安装 Helm

如果你想使用特定版本的 Helm，你可以按照[`helm.sh/docs/intro/install/`](https://helm.sh/docs/intro/install/)中的特定版本文档来安装它。对于我们的用例，我们将简单地使用`get helm`脚本，它将安装最新版本。

您可以按照以下步骤获取并运行脚本：

```
curl -fsSL -o get_helm.sh https://raw.githubusercontent.com/helm/helm/master/scripts/get-helm-3
chmod 700 get_helm.sh
./get_helm.sh
```

现在，我们应该能够运行`helm`命令了。默认情况下，Helm 将自动使用您现有的`kubeconfig`集群和上下文，因此为了在 Helm 中切换集群，您只需要使用`kubectl`来更改您的`kubeconfig`文件，就像您通常做的那样。

要使用 Helm 安装应用程序，请运行`helm install`命令。但是 Helm 是如何决定安装什么和如何安装的呢？我们需要讨论 Helm 图表、Helm 仓库和 Helm 发布的概念。

### Helm 图表、仓库和发布

Helm 提供了一种使用变量在 Kubernetes 上模板化和部署应用程序的方法。为了做到这一点，我们通过一组模板来指定工作负载，这被称为*Helm 图表*。

Helm 图表由一个或多个模板、一些图表元数据和一个`values`文件组成，该文件用最终值填充模板变量。在实践中，您将为每个环境（或应用程序，如果您正在为多个应用程序重用模板）拥有一个`values`文件，该文件将使用新配置填充共享模板。然后，模板和值的组合将用于在集群中安装或部署应用程序。

那么，您可以将 Helm 图表存储在哪里？您可以像对待任何其他 Kubernetes YAML 一样将它们放在 Git 存储库中（这对大多数用例都适用），但 Helm 还支持存储库的概念。Helm 存储库由 URL 表示，可以包含多个 Helm 图表。例如，Helm 在[`hub.helm.sh/charts`](https://hub.helm.sh/charts)上有自己的官方存储库。同样，每个 Helm 图表由一个包含元数据文件的文件夹、一个`Chart.yaml`文件、一个或多个模板文件以及一个可选的 values 文件组成。

为了安装具有本地 values 文件的本地 Helm 图表，您可以为每个传递路径到`helm install`，如以下命令所示：

```
helm install -f values.yaml /path/to/chart/root
```

然而，对于常用的安装图表，您也可以直接从图表存储库安装图表，并且您还可以选择将自定义存储库添加到本地 Helm 中，以便能够轻松地从非官方来源安装图表。

例如，为了通过官方 Helm 图表安装 Drupal，您可以运行以下命令：

```
helm install -f values.yaml stable/drupal
```

此代码从官方 Helm 图表存储库安装图表。要使用自定义存储库，您只需要首先将其添加到 Helm 中。例如，要安装托管在`jetstack` Helm 存储库上的`cert-manager`，我们可以执行以下操作：

```
helm repo add jetstack https://charts.jetstack.io
helm install certmanager --namespace cert-manager jetstack/cert-manager
```

此代码将`jetstack` Helm 存储库添加到本地 Helm CLI 工具中，然后通过其中托管的图表安装`cert-manager`。我们还将发布命名为`cert-manager`。Helm 发布是 Helm V3 中使用 Kubernetes secrets 实现的概念。当我们在 Helm 中创建一个发布时，它将作为同一命名空间中的一个 secret 存储。

为了说明这一点，我们可以使用前面的`install`命令创建一个 Helm 发布。现在让我们来做吧：

```
helm install certmanager --namespace cert-manager jetstack/cert-manager
```

该命令应该产生以下输出，具体内容可能会有所不同，取决于当前的 Cert Manager 版本。为了便于阅读，我们将输出分为两个部分。

首先，命令的输出给出了 Helm 发布的状态：

```
NAME: certmanager
LAST DEPLOYED: Sun May 23 19:07:04 2020
NAMESPACE: cert-manager
STATUS: deployed
REVISION: 1
TEST SUITE: None
```

正如您所看到的，此部分包含部署的时间戳、命名空间信息、修订版本和状态。接下来，我们将看到输出的注释部分：

```
NOTES:
cert-manager has been deployed successfully!
In order to begin issuing certificates, you will need to set up a ClusterIssuer
or Issuer resource (for example, by creating a 'letsencrypt-staging' issuer).
More information on the different types of issuers and how to configure them
can be found in our documentation:
https://cert-manager.io/docs/configuration/
For information on how to configure cert-manager to automatically provision
Certificates for Ingress resources, take a look at the `ingress-shim`
documentation:
https://cert-manager.io/docs/usage/ingress/
```

正如您所看到的，我们的 Helm `install`命令已经成功，这也给了我们一些来自`cert-manager`的信息，告诉我们如何使用它。这个输出在安装 Helm 软件包时可能会很有帮助，因为它们有时包括先前片段中的文档。现在，为了查看我们的 Kubernetes 中的发布对象是什么样子，我们可以运行以下命令：

```
Kubectl get secret -n cert-manager
```

这将产生以下输出：

![图 11.1 – 来自 kubectl 的 Secrets 列表输出](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cld-ntv-k8s/img/B14790_11_001.jpg)

图 11.1 – 来自 kubectl 的 Secrets 列表输出

正如您所看到的，其中一个密钥的类型为`helm.sh/release.v1`。这是 Helm 用来跟踪 Cert Manager 发布的密钥。

最后，要在 Helm CLI 中查看发布列表，我们可以运行以下命令：

```
helm ls -A
```

此命令将列出所有命名空间中的 Helm 发布（就像`kubectl get pods -A`会列出所有命名空间中的 pod 一样）。输出将如下所示：

![图 11.2 – Helm 发布列表输出](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cld-ntv-k8s/img/B14790_11_002.jpg)

图 11.2 – Helm 发布列表输出

现在，Helm 有更多的组件，包括`升级`、`回滚`等，我们将在下一节中进行审查。为了展示 Helm 的功能，我们将从头开始创建和安装一个图表。

### 创建 Helm 图表

因此，我们希望为我们的应用程序创建一个 Helm 图表。让我们开始吧。我们的目标是轻松地将一个简单的 Node.js 应用程序部署到多个环境中。为此，我们将创建一个包含应用程序组件的图表，然后将其与三个单独的值文件（`dev`、`staging`和`production`）结合起来，以便将我们的应用程序部署到三个环境中。

让我们从 Helm 图表的文件夹结构开始。正如我们之前提到的，Helm 图表由模板、元数据文件和可选值组成。我们将在实际安装图表时注入这些值，但我们可以将我们的文件夹结构设计成这样：

```
Chart.yaml
charts/
templates/
dev-values.yaml
staging-values.yaml
production-values.yaml
```

我们还没有提到的一件事是，您实际上可以在现有图表中拥有一个 Helm 图表的文件夹！这些子图表可以将复杂的应用程序分解为组件，使其易于管理。对于本书的目的，我们将不使用子图表，但是如果您的应用程序变得过于复杂或模块化，这是一个有价值的功能。

此外，您可以看到我们为每个环境都有一个不同的环境文件，在安装命令期间我们将使用它们。

那么，`Chart.yaml`文件是什么样子的呢？该文件将包含有关图表的一些基本元数据，并且通常看起来至少是这样的：

```
apiVersion: v2
name: mynodeapp
version: 1.0.0
```

`Chart.yaml`文件支持许多可选字段，您可以在[`helm.sh/docs/topics/charts/`](https://helm.sh/docs/topics/charts/)中查看，但是对于本教程的目的，我们将保持简单。强制字段是`apiVersion`，`name`和`version`。

在我们的`Chart.yaml`文件中，`apiVersion`对应于图表对应的 Helm 版本。有点令人困惑的是，当前版本的 Helm，Helm V3，使用`apiVersion` `v2`，而包括 Helm V2 在内的旧版本的 Helm 也使用`apiVersion` `v2`。

接下来，`name`字段对应于我们图表的名称。这相当容易理解，尽管请记住，我们有能力为图表的特定版本命名 - 这对于多个环境非常方便。

最后，我们有`version`字段，它对应于图表的版本。该字段支持**SemVer**（语义化版本）。

那么，我们的模板实际上是什么样子的呢？Helm 图表在底层使用 Go 模板库（有关更多信息，请参见[`golang.org/pkg/text/template/`](https://golang.org/pkg/text/template/)），并支持各种强大的操作、辅助函数等等。现在，我们将保持极其简单，以便让您了解基础知识。有关 Helm 图表创建的全面讨论可能需要一本专门的书！

首先，我们可以使用 Helm CLI 命令自动生成我们的`Chart`文件夹，其中包括所有先前的文件和文件夹，减去为您生成的子图和值文件。让我们试试吧 - 首先使用以下命令创建一个新的 Helm 图表：

```
helm create myfakenodeapp
```

这个命令将在名为`myfakenodeapp`的文件夹中创建一个自动生成的图表。让我们使用以下命令检查我们`templates`文件夹的内容：

```
Ls myfakenodeapp/templates
```

这个命令将产生以下输出：

```
helpers.tpl
deployment.yaml
NOTES.txt
service.yaml
```

这个自动生成的图表可以作为起点帮助很多，但是对于本教程的目的，我们将从头开始制作这些。

创建一个名为`mynodeapp`的新文件夹，并将我们之前向您展示的`Chart.yaml`文件放入其中。然后，在里面创建一个名为`templates`的文件夹。

要记住的一件事是：一个 Kubernetes 资源 YAML 本身就是一个有效的 Helm 模板。在模板中使用任何变量并不是必需的。你可以只编写普通的 YAML，Helm 安装仍然可以工作。

为了展示这一点，让我们从我们的模板文件夹中添加一个单个模板文件开始。将其命名为`deployment.yaml`，并包含以下非变量 YAML：

deployment.yaml:

```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: frontend-myapp
  labels:
    app: frontend-myapp
spec:
  replicas: 2
  selector:
    matchLabels:
      app: frontend-myapp
  template:
    metadata:
      labels:
        app: frontend-myapp
    spec:
      containers:
      - name: frontend-myapp
        image: myrepo/myapp:1.0.0
        ports:
        - containerPort: 80
```

正如你所看到的，这个 YAML 只是一个普通的 Kubernetes 资源 YAML。我们在我们的模板中没有使用任何变量。

现在，我们有足够的内容来实际安装我们的图表。让我们接下来做这件事。

### 安装和卸载 Helm 图表

要使用 Helm V3 安装图表，你需要从图表的`root`目录运行`helm install`命令：

```
helm install myapp .
```

这个安装命令创建了一个名为`frontend-app`的 Helm 发布，并安装了我们的图表。现在，我们的图表只包括一个具有两个 pod 的单个部署，我们应该能够通过以下命令在我们的集群中看到它正在运行：

```
kubectl get deployment
```

这应该会产生以下输出：

```
NAMESPACE  NAME            READY   UP-TO-DATE   AVAILABLE   AGE
default    frontend-myapp  2/2     2            2           2m
```

从输出中可以看出，我们的 Helm `install`命令已经成功在 Kubernetes 中创建了一个部署对象。

卸载我们的图表同样简单。我们可以通过运行以下命令来安装通过我们的图表安装的所有 Kubernetes 资源：

```
helm uninstall myapp
```

这个`uninstall`命令（在 Helm V2 中是`delete`）只需要我们 Helm 发布的名称。

到目前为止，我们还没有使用 Helm 的真正功能 - 我们一直把它当作`kubectl`的替代品，没有添加任何功能。让我们通过在我们的图表中实现一些变量来改变这一点。

### 使用模板变量

向我们的 Helm 图表模板添加变量就像使用双括号 - `{{ }}` - 语法一样简单。我们在双括号中放入的内容将直接从我们在安装图表时使用的值中取出，使用点符号表示法。

让我们看一个快速的例子。到目前为止，我们的应用名称（和容器镜像名称/版本）都是硬编码到我们的 YAML 文件中的。如果我们想要使用我们的 Helm 图表部署不同的应用程序或不同的应用程序版本，这将极大地限制我们。

为了解决这个问题，我们将在我们的图表中添加模板变量。看一下这个结果模板：

Templated-deployment.yaml:

```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: frontend-{{ .Release.Name }}
  labels:
    app: frontend-{{ .Release.Name }}
    chartVersion: {{ .Chart.version }}
spec:
  replicas: 2
  selector:
    matchLabels:
      app: frontend-{{ .Release.Name }}
  template:
    metadata:
      labels:
        app: frontend-{{ .Release.Name }}
    spec:
      containers:
      - name: frontend-{{ .Release.Name }}
        image: myrepo/{{ .Values.image.name }}
:{{ .Values.image.tag }}
        ports:
        - containerPort: 80
```

让我们浏览一下这个 YAML 文件，审查一下我们的变量。在这个文件中，我们使用了几种不同类型的变量，但它们都使用相同的点符号表示法。

Helm 实际上支持几种不同的顶级对象。这些是您可以在模板中引用的主要对象：

+   `.Chart`：用于引用`Chart.yaml`文件中的元数据值

+   `.Values`：用于引用在安装时从`values`文件传递到图表中的值

+   `.Template`：用于引用当前模板文件的一些信息

+   `.Release`：用于引用有关 Helm 发布的信息

+   `.Files`：用于引用图表中不是 YAML 模板的文件（例如`config`文件）

+   `.Capabilities`：用于引用目标 Kubernetes 集群的信息（换句话说，版本）

在我们的 YAML 文件中，我们正在使用其中的几个。首先，我们在几个地方引用我们发布的`name`（包含在`.Release`对象中）。接下来，我们正在利用`Chart`对象将元数据注入`chartVersion`键中。最后，我们使用`Values`对象引用容器镜像的`name`和`tag`。

现在，我们缺少的最后一件事是我们将通过`values.yaml`注入的实际值，或者通过 CLI 命令。其他所有内容将使用`Chart.yaml`创建，或者我们将通过`helm`命令本身在运行时注入的值。

考虑到这一点，让我们从我们的模板创建我们的值文件，我们将在其中传递我们的图像`name`和`tag`。因此，让我们以正确的格式包含它们：

```
image:
  name: myapp
  tag: 2.0.1
```

现在我们可以通过我们的 Helm 图表安装我们的应用程序！使用以下命令：

```
helm install myrelease -f values.yaml .
```

正如您所看到的，我们正在使用`-f`键传递我们的值（您也可以使用`--values`）。此命令将安装我们应用程序的发布。

一旦我们有了一个发布，我们就可以使用 Helm CLI 升级到新版本或回滚到旧版本-我们将在下一节中介绍这一点。

### 升级和回滚

现在我们有了一个活动的 Helm 发布，我们可以升级它。让我们对我们的`values.yaml`进行一些小改动：

```
image:
  name: myapp
  tag: 2.0.2
```

要使这成为我们发布的新版本，我们还需要更改我们的图表 YAML：

```
apiVersion: v2
name: mynodeapp
version: 1.0.1
```

现在，我们可以使用以下命令升级我们的发布：

```
helm upgrade myrelease -f values.yaml .
```

如果出于任何原因，我们想回滚到早期版本，我们可以使用以下命令：

```
helm rollback myrelease 1.0.0
```

正如您所看到的，Helm 允许无缝地对应用程序进行模板化、发布、升级和回滚。正如我们之前提到的，Kustomize 达到了许多相同的点，但它的方式大不相同-让我们看看。 

## 使用 Kustomize 与 Kubernetes

虽然 Helm 图表可能会变得非常复杂，但 Kustomize 使用 YAML 而不使用任何变量，而是使用基于补丁和覆盖的方法将不同的配置应用于一组基本的 Kubernetes 资源。

使用 Kustomize 非常简单，正如我们在本章前面提到的，不需要先决条件 CLI 工具。一切都可以通过使用`kubectl apply -k /path/kustomize.yaml`命令来完成，而无需安装任何新内容。但是，我们还将演示使用 Kustomize CLI 工具的流程。

重要说明

要安装 Kustomize CLI 工具，您可以在[`kubernetes-sigs.github.io/kustomize/installation`](https://kubernetes-sigs.github.io/kustomize/installation)上查看安装说明。

目前，安装使用以下命令：

```
curl -s "https://raw.githubusercontent.com/\
kubernetes-sigs/kustomize/master/hack/install_kustomize.sh"  | bash
```

现在我们已经安装了 Kustomize，让我们将 Kustomize 应用于我们现有的用例。我们将从我们的普通 Kubernetes YAML 开始（在我们开始添加 Helm 变量之前）：

plain-deployment.yaml：

```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: frontend-myapp
  labels:
    app: frontend-myapp
spec:
  replicas: 2
  selector:
    matchLabels:
      app: frontend-myapp
  template:
    metadata:
      labels:
        app: frontend-myapp
    spec:
      containers:
      - name: frontend-myapp
        image: myrepo/myapp:1.0.0
        ports:
        - containerPort: 80
```

创建了初始的`deployment.yaml`后，我们现在可以创建一个 Kustomization 文件，我们称之为`kustomize.yaml`。

当我们稍后使用`-k`参数调用`kubectl`命令时，`kubectl`将查找此`kustomize` YAML 文件，并使用它来确定要应用到传递给`kubectl`命令的所有其他 YAML 文件的补丁。

Kustomize 让我们可以修补单个值或设置自动设置的常见值。一般来说，Kustomize 会创建新行，或者如果 YAML 中的键已经存在，则更新旧行。有三种方法可以应用这些更改：

+   在 Kustomization 文件中直接指定更改。

+   使用`PatchStrategicMerge`策略和`patch.yaml`文件以及 Kustomization 文件。

+   使用`JSONPatch`策略和`patch.yaml`文件以及 Kustomization 文件。

让我们从专门用于修补 YAML 的 Kustomization 文件开始。

### 直接在 Kustomization 文件中指定更改

如果我们想在 Kustomization 文件中直接指定更改，我们可以这样做，但我们的选择有些有限。我们可以在 Kustomization 文件中使用的键的类型如下：

+   `resources`-指定应在应用补丁时自定义的文件

+   `transformers`-直接从 Kustomization 文件中应用补丁的方法

+   `generators`-从 Kustomization 文件创建新资源的方法

+   `meta`-设置可以影响生成器、转换器和资源的元数据字段

如果我们想在 Kustomization 文件中指定直接补丁，我们需要使用转换器。前面提到的`PatchStrategicMerge`和`JSONPatch`合并策略是两种转换器。然而，为了直接应用更改到 Kustomization 文件，我们可以使用几种转换器之一，其中包括`commonLabels`、`images`、`namePrefix`和`nameSuffix`。

在下面的 Kustomization 文件中，我们正在使用`commonLabels`和`images`转换器对我们的初始部署`YAML`进行更改。

Deployment-kustomization-1.yaml：

```
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
- deployment.yaml
namespace: default
commonLabels:
  app: frontend-app
images:
  - name: frontend-myapp
    newTag: 2.0.0
    newName: frontend-app-1
```

这个特定的`Kustomization.yaml`文件将图像标签从`1.0.0`更新为`2.0.0`，将应用程序的名称从`frontend-myapp`更新为`frontend-app`，并将容器的名称从`frontend-myapp`更新为`frontend-app-1`。

要全面了解每个转换器的具体细节，您可以查看[Kustomize 文档](https://kubernetes-sigs.github.io/kustomize/)。Kustomize 文件假定`deployment.yaml`与其自身在同一个文件夹中。

要查看当我们的 Kustomize 文件应用到我们的部署时的结果，我们可以使用 Kustomize CLI 工具。我们将使用以下命令生成经过自定义处理的输出：

```
kustomize build deployment-kustomization1.yaml
```

该命令将给出以下输出：

```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: frontend-myapp
  labels:
    app: frontend-app
spec:
  replicas: 2
  selector:
    matchLabels:
      app: frontend-app
  template:
    metadata:
      labels:
        app: frontend-app
    spec:
      containers:
      - name: frontend-app-1
        image: myrepo/myapp:2.0.0
        ports:
        - containerPort: 80
```

如您所见，我们的 Kustomization 文件中的自定义已经应用。因为`kustomize build`命令输出 Kubernetes YAML，我们可以轻松地将输出部署到 Kubernetes，如下所示：

```
kustomize build deployment-kustomization.yaml | kubectl apply -f -
```

接下来，让我们看看如何使用带有`PatchStrategicMerge`的 YAML 文件来修补我们的部署。

### 使用 PatchStrategicMerge 指定更改

为了说明`PatchStrategicMerge`策略，我们再次从相同的`deployment.yaml`文件开始。这次，我们将通过`kustomization.yaml`文件和`patch.yaml`文件的组合来发布我们的更改。

首先，让我们创建我们的`kustomization.yaml`文件，它看起来像这样：

Deployment-kustomization-2.yaml：

```
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
- deployment.yaml
namespace: default
patchesStrategicMerge:
  - deployment-patch-1.yaml
```

正如您所见，我们的 Kustomization 文件在`patchesStrategicMerge`部分引用了一个新文件`deployment-patch-1.yaml`。这里可以添加任意数量的补丁 YAML 文件。

然后，我们的`deployment-patch-1.yaml`文件是一个简单的文件，镜像了我们的部署并包含我们打算进行的更改。它看起来像这样：

Deployment-patch-1.yaml：

```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: frontend-myapp
  labels:
    app: frontend-myapp
spec:
  replicas: 4
```

这个补丁文件是原始部署中字段的一个子集。在这种情况下，它只是将 `replicas` 从 `2` 更新为 `4`。再次应用更改，我们可以使用以下命令：

```
 kustomize build deployment-kustomization2.yaml
```

但是，我们也可以在 `kubectl` 命令中使用 `-k` 标志！它看起来是这样的：

```
Kubectl apply -k deployment-kustomization2.yaml
```

这个命令相当于以下内容：

```
kustomize build deployment-kustomization2.yaml | kubectl apply -f -
```

与 `PatchStrategicMerge` 类似，我们还可以在我们的 Kustomization 中指定基于 JSON 的补丁 - 现在让我们来看看。

### 使用 JSONPatch 指定更改

要使用 JSON 补丁文件指定更改，该过程与涉及 YAML 补丁的过程非常相似。

首先，我们需要我们的 Kustomization 文件。它看起来像这样：

Deployment-kustomization-3.yaml:

```
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
- deployment.yaml
namespace: default
patches:
- path: deployment-patch-2.json
  target:
    group: apps
    version: v1
    kind: Deployment
    name: frontend-myapp
```

正如您所看到的，我们的 Kustomize 文件有一个 `patches` 部分，其中引用了一个 JSON 补丁文件以及一个目标。您可以在此部分引用尽可能多的 JSON 补丁。`target` 用于确定在资源部分中指定的哪个 Kubernetes 资源将接收补丁。

最后，我们需要我们的补丁 JSON 本身，它看起来像这样：

Deployment-patch-2.json:

```
[
  {
   "op": "replace",
   "path": "/spec/template/spec/containers/0/name",
   "value": "frontend-myreplacedapp"
  }
]
```

应用此补丁时，将对我们第一个容器的名称执行 `replace` 操作。您可以沿着我们原始的 `deployment.yaml` 文件路径查看，以查看它引用了第一个容器的名称。它将用新值 `frontend-myreplacedapp` 替换此名称。

现在我们已经在 Kubernetes 资源模板化和使用 Kustomize 和 Helm 进行发布方面有了坚实的基础，我们可以继续自动化部署到 Kubernetes。在下一节中，我们将看到两种实现 CI/CD 的模式。

# 了解 Kubernetes 上的 CI/CD 范式 - 集群内和集群外

对 Kubernetes 进行持续集成和部署可以采用多种形式。

大多数 DevOps 工程师将熟悉 Jenkins、TravisCI 等工具。这些工具非常相似，它们提供了一个执行环境来构建应用程序，执行测试，并在受控环境中调用任意的 Bash 脚本。其中一些工具在容器内运行命令，而其他工具则不会。

在涉及 Kubernetes 时，有多种思路和使用这些工具的方式。还有一种较新的 CI/CD 平台，它们与 Kubernetes 原语更紧密地耦合，并且许多平台都是设计在集群本身上运行的。

为了彻底讨论工具如何与 Kubernetes 相关，我们将把我们的流水线分为两个逻辑步骤：

1.  **构建**：编译、测试应用程序、构建容器映像，并发送到映像仓库

1.  **部署**：通过 kubectl、Helm 或其他工具更新 Kubernetes 资源

为了本书的目的，我们将主要关注第二个部署为重点的步骤。虽然许多可用的选项都处理构建和部署步骤，但构建步骤几乎可以发生在任何地方，并且不值得我们在涉及 Kubernetes 具体细节的书中关注。

考虑到这一点，为了讨论我们的工具选项，我们将把我们的工具集分为两个类别，就我们流水线的部署部分而言：

+   集群外 CI/CD

+   集群内 CI/CD

## 集群外 CI/CD

在第一种模式中，我们的 CI/CD 工具运行在目标 Kubernetes 集群之外。我们称之为集群外 CI/CD。存在一个灰色地带，即工具可能在专注于 CI/CD 的单独 Kubernetes 集群中运行，但我们暂时忽略该选项，因为这两个类别之间的差异仍然基本有效。

您经常会发现行业标准的工具，如 Jenkins 与这种模式一起使用，但任何具有运行脚本和以安全方式保留秘钥的能力的 CI 工具都可以在这里工作。一些例子是**GitLab CI**、**CircleCI**、**TravisCI**、**GitHub Actions**和**AWS CodeBuild**。Helm 也是这种模式的重要组成部分，因为集群外 CI 脚本可以调用 Helm 命令来代替 kubectl。

这种模式的一些优点在于其简单性和可扩展性。这是一种“推送”模式，代码的更改会同步触发 Kubernetes 工作负载的更改。

在推送到多个集群时，集群外 CI/CD 的一些弱点是可伸缩性，以及需要在 CI/CD 管道中保留集群凭据，以便它能够调用 kubectl 或 Helm 命令。

## 集群内 CI/CD

在第二种模式中，我们的工具在与我们的应用程序相同的集群上运行，这意味着 CI/CD 发生在与我们的应用程序相同的 Kubernetes 上下文中，作为 pod。我们称之为集群内 CI/CD。这种集群内模式仍然可以使“构建”步骤发生在集群外，但部署步骤发生在集群内。

自从 Kubernetes 发布以来，这些类型的工具已经变得越来越受欢迎，许多使用自定义资源定义和自定义控制器来完成它们的工作。一些例子是 FluxCD、Argo CD、JenkinsX 和 Tekton Pipelines。在这些工具中，GitOps 模式很受欢迎，其中 Git 存储库被用作集群上应该运行什么应用程序的真相来源。

内部 CI/CD 模式的一些优点是可伸缩性和安全性。通过使用 GitOps 操作模型，使集群从 GitHub“拉取”更改，解决方案可以扩展到许多集群。此外，它消除了在 CI/CD 系统中保留强大的集群凭据的需要，而是在集群本身上具有 GitHub 凭据，从安全性的角度来看可能更好。

内部 CI/CD 模式的弱点包括复杂性，因为这种拉取操作略微异步（因为`git pull`通常在循环中发生，不总是在推送更改时发生）。

# 使用 Kubernetes 实现内部和外部 CI/CD

由于在 Kubernetes 中有很多 CI/CD 的选择，我们将选择两个选项并逐一实施它们，这样您可以比较它们的功能集。首先，我们将在 AWS CodeBuild 上实施 CI/CD 到 Kubernetes，这是一个很好的示例实现，可以在任何可以运行 Bash 脚本的外部 CI 系统中重复使用，包括 Bitbucket Pipelines、Jenkins 等。然后，我们将转向 FluxCD，这是一种基于 GitOps 的内部 CI 选项，它是 Kubernetes 原生的。让我们从外部选项开始。

## 使用 AWS CodeBuild 实现 Kubernetes CI

正如前面提到的，我们的 AWS CodeBuild CI 实现将很容易在任何基于脚本的 CI 系统中复制。在许多情况下，我们将使用的流水线 YAML 定义几乎相同。此外，正如我们之前讨论的，我们将跳过容器镜像的实际构建。我们将专注于实际的部署部分。

快速介绍一下 AWS CodeBuild，它是一个基于脚本的 CI 工具，可以运行 Bash 脚本，就像许多其他类似的工具一样。在 AWS CodePipeline 的上下文中，可以将多个独立的 AWS CodeBuild 步骤组合成更大的流水线。

在我们的示例中，我们将同时使用 AWS CodeBuild 和 AWS CodePipeline。我们不会深入讨论如何使用这两个工具，而是将我们的讨论专门与如何将它们用于部署到 Kubernetes 联系起来。

重要提示

我们强烈建议您阅读和审阅 CodePipeline 和 CodeBuild 的文档，因为我们在本章中不会涵盖所有基础知识。您可以在[`docs.aws.amazon.com/codebuild/latest/userguide/welcome.html`](https://docs.aws.amazon.com/codebuild/latest/userguide/welcome.html)找到 CodeBuild 的文档，以及[`docs.aws.amazon.com/codepipeline/latest/userguide/welcome.html`](https://docs.aws.amazon.com/codepipeline/latest/userguide/welcome.html)找到 CodePipeline 的文档。

在实践中，您将拥有两个 CodePipeline，每个都有一个或多个 CodeBuild 步骤。第一个 CodePipeline 在 AWS CodeCommit 或其他 Git 仓库（如 GitHub）中的代码更改时触发。

这个流水线的第一个 CodeBuild 步骤运行测试并构建容器镜像，将镜像推送到 AWS **弹性容器仓库**（**ECR**）。第一个流水线的第二个 CodeBuild 步骤部署新的镜像到 Kubernetes。

第二个 CodePipeline 在我们提交对 Kubernetes 资源文件（基础设施仓库）的次要 Git 仓库的更改时触发。它将使用相同的流程更新 Kubernetes 资源。

让我们从第一个 CodePipeline 开始。如前所述，它包含两个 CodeBuild 步骤：

1.  首先，测试和构建容器镜像，并将其推送到 ECR

1.  其次，部署更新后的容器到 Kubernetes。

正如我们在本节前面提到的，我们不会在代码到容器镜像的流水线上花费太多时间，但这里有一个示例（不适用于生产）的`codebuild` YAML，用于实现这一步骤：

Pipeline-1-codebuild-1.yaml:

```
version: 0.2
phases:
  build:
    commands:
      - npm run build
  test:
    commands:
      - npm test
  containerbuild:
    commands:
      - docker build -t $ECR_REPOSITORY/$IMAGE_NAME:$IMAGE_TAG .
  push:
    commands:
      - docker push_$ECR_REPOSITORY/$IMAGE_NAME:$IMAGE_TAG
```

这个 CodeBuild 流水线包括四个阶段。CodeBuild 流水线规范是用 YAML 编写的，并包含一个与 CodeBuild 规范版本对应的`version`标签。然后，我们有一个`phases`部分，按顺序执行。这个 CodeBuild 首先运行`build`命令，然后在测试阶段运行`test`命令。最后，`containerbuild`阶段创建容器镜像，`push`阶段将镜像推送到我们的容器仓库。

需要记住的一件事是，CodeBuild 中每个以`$`开头的值都是环境变量。这些可以通过 AWS 控制台或 AWS CLI 进行自定义，并且有些可以直接来自 Git 仓库。

现在让我们看一下我们第一个 CodePipeline 的第二个 CodeBuild 步骤的 YAML：

Pipeline-1-codebuild-2.yaml:

```
version: 0.2
phases:
  install:
    commands:
      - curl -o kubectl https://amazon-eks.s3.us-west-2.amazonaws.com/1.16.8/2020-04-16/bin/darwin/amd64/kubectl  
      - chmod +x ./kubectl
      - mkdir -p $HOME/bin && cp ./kubectl $HOME/bin/kubectl && export PATH=$PATH:$HOME/bin
      - echo 'export PATH=$PATH:$HOME/bin' >> ~/.bashrc
      - source ~/.bashrc
  pre_deploy:
    commands:
      - aws eks --region $AWS_DEFAULT_REGION update-kubeconfig --name $K8S_CLUSTER
  deploy:
    commands:
      - cd $CODEBUILD_SRC_DIR
      - kubectl set image deployment/$KUBERNETES-DEPLOY-NAME myrepo:"$IMAGE_TAG"
```

让我们来分解这个文件。我们的 CodeBuild 设置分为三个阶段：`install`、`pre_deploy`和`deploy`。在`install`阶段，我们安装 kubectl CLI 工具。

然后，在`pre_deploy`阶段，我们使用 AWS CLI 命令和一些环境变量来更新我们的`kubeconfig`文件，以便与我们的 EKS 集群通信。在任何其他 CI 工具（或者不使用 EKS 时），您可以使用不同的方法为您的 CI 工具提供集群凭据。在这里使用安全选项很重要，因为直接在 Git 仓库中包含`kubeconfig`文件是不安全的。通常，一些环境变量的组合在这里会很好。Jenkins、CodeBuild、CircleCI 等都有它们自己的系统来处理这个问题。

最后，在`deploy`阶段，我们使用`kubectl`来使用第一个 CodeBuild 步骤中指定的新镜像标签更新我们的部署（也包含在一个环境变量中）。这个`kubectl rollout restart`命令将确保为我们的部署启动新的 pod。结合使用`imagePullPolicy`的`Always`，这将导致我们的新应用程序版本被部署。

在这种情况下，我们正在使用 ECR 中特定的镜像标签名称来修补我们的部署。`$IMAGE_TAG`环境变量将自动填充为 GitHub 中最新的标签，因此我们可以使用它来自动将新的容器镜像滚动到我们的部署中。

接下来，让我们来看看我们的第二个 CodePipeline。这个 Pipeline 只包含一个步骤 - 它监听来自一个单独的 GitHub 仓库的更改，我们的“基础设施仓库”。这个仓库不包含应用程序本身的代码，而是 Kubernetes 资源的 YAML 文件。因此，我们可以更改一个 Kubernetes 资源的 YAML 值 - 例如，在部署中的副本数量，并在 CodePipeline 运行后在 Kubernetes 中看到它更新。这种模式可以很容易地扩展到使用 Helm 或 Kustomize。

让我们来看看我们第二个 CodePipeline 的第一个，也是唯一的步骤。

Pipeline-2-codebuild-1.yaml:

```
version: 0.2
phases:
  install:
    commands:
      - curl -o kubectl https://amazon-eks.s3.us-west-2.amazonaws.com/1.16.8/2020-04-16/bin/darwin/amd64/kubectl  
      - chmod +x ./kubectl
      - mkdir -p $HOME/bin && cp ./kubectl $HOME/bin/kubectl && export PATH=$PATH:$HOME/bin
      - echo 'export PATH=$PATH:$HOME/bin' >> ~/.bashrc
      - source ~/.bashrc
  pre_deploy:
    commands:
      - aws eks --region $AWS_DEFAULT_REGION update-kubeconfig --name $K8S_CLUSTER
  deploy:
    commands:
      - cd $CODEBUILD_SRC_DIR
      - kubectl apply -f .
```

正如您所看到的，这个 CodeBuild 规范与我们之前的规范非常相似。与以前一样，我们安装 kubectl 并准备好与我们的 Kubernetes 集群一起使用。由于我们在 AWS 上运行，我们使用 AWS CLI 来完成，但这可以通过许多方式来完成，包括只需将`Kubeconfig`文件添加到我们的 CodeBuild 环境中。

不同之处在于，我们不是用新版本的应用程序来修补特定部署，而是在管道中运行全面的`kubectl apply`命令，同时将整个基础设施文件夹传输进来。这样一来，Git 中进行的任何更改都会应用到我们集群中的资源上。例如，如果我们通过更改`deployment.yaml`文件中的值，将我们的部署从 2 个副本扩展到 20 个副本，它将在这个 CodePipeline 步骤中部署到 Kubernetes，并且部署将会扩展。

现在我们已经介绍了使用集群外 CI/CD 环境对 Kubernetes 资源进行更改的基础知识，让我们来看看一个完全不同的 CI 范式，其中流水线在我们的集群上运行。

## 使用 FluxCD 实施 Kubernetes CI

对于我们的集群内 CI 工具，我们将使用**FluxCD**。集群内 CI 有几个选项，包括**ArgoCD**和**JenkinsX**，但我们喜欢**FluxCD**相对简单的特点，以及它可以自动更新 Pod 的新容器版本而无需任何额外配置。作为一个额外的变化，我们将使用 FluxCD 的 Helm 集成来管理部署。让我们从安装 FluxCD 开始（我们假设您已经从本章的前几部分安装了 Helm）。这些安装遵循了书写本书时的官方 FluxCD Helm 兼容性安装说明。

官方的 FluxCD 文档可以在[`docs.fluxcd.io/`](https://docs.fluxcd.io/)找到，我们强烈建议您去看一看！FluxCD 是一个非常复杂的工具，我们在本书中只是浅尝辄止。全面的审查不在范围内 - 我们只是试图向您介绍集群内 CI/CD 模式和相关工具。

让我们从在我们的集群上安装 FluxCD 开始我们的审查。

### 安装 FluxCD（H3）

FluxCD 可以在几个步骤中使用 Helm 轻松安装：

1.  首先，我们需要添加 Flux Helm 图表存储库：

```
helm repo add fluxcd https://charts.fluxcd.io
```

1.  接下来，我们需要添加一个自定义资源定义，FluxCD 需要这样做才能与 Helm 发布一起工作：

```
kubectl apply -f https://raw.githubusercontent.com/fluxcd/helm-operator/master/deploy/crds.yaml
```

1.  在我们安装 FluxCD Operator（这是 FluxCD 在 Kubernetes 上的核心功能）和 FluxCD Helm Operator 之前，我们需要为 FluxCD 创建一个命名空间。

```
kubectl create namespace flux
```

现在我们可以安装 FluxCD 的主要组件，但我们需要为 FluxCD 提供有关我们的 Git 存储库的一些额外信息。

为什么？因为 FluxCD 使用 GitOps 模式进行更新和部署。这意味着 FluxCD 将每隔几分钟主动访问我们的 Git 仓库，而不是响应 Git 钩子，比如 CodeBuild。

FluxCD 还将通过拉取策略响应新的 ECR 镜像，但我们稍后再讨论这一点。

1.  要安装 FluxCD 的主要组件，请运行以下两个命令，并将`GITHUB_USERNAME`和`REPOSITORY_NAME`替换为您将在其中存储工作负载规范（Kubernetes YAML 或 Helm 图表）的 GitHub 用户和仓库。

这组指令假设 Git 仓库是公开的，但实际上它可能不是。由于大多数组织使用私有仓库，FluxCD 有特定的配置来处理这种情况-只需查看文档[`docs.fluxcd.io/en/latest/tutorials/get-started-helm/`](https://docs.fluxcd.io/en/latest/tutorials/get-started-helm/)。事实上，为了看到 FluxCD 的真正力量，无论如何你都需要给它对 Git 仓库的高级访问权限，因为 FluxCD 可以写入你的 Git 仓库，并在创建新的容器镜像时自动更新清单。但是，在本书中我们不会涉及这个功能。FluxCD 的文档绝对值得仔细阅读，因为这是一个具有许多功能的复杂技术。要告诉 FluxCD 要查看哪个 GitHub 仓库，你可以在安装时使用 Helm 设置变量，就像下面的命令一样：

```
helm upgrade -i flux fluxcd/flux \
--set git.url=git@github.com:GITHUB_USERNAME/REPOSITORY_NAME \
--namespace flux
helm upgrade -i helm-operator fluxcd/helm-operator \
--set git.ssh.secretName=flux-git-deploy \
--namespace flux
```

正如你所看到的，我们需要传递我们的 GitHub 用户名，仓库的名称，以及在 Kubernetes 中用于 GitHub 秘钥的名称。

此时，FluxCD 已完全安装在我们的集群中，并指向我们在 Git 上的基础设施仓库！如前所述，这个 GitHub 仓库将包含 Kubernetes YAML 或 Helm 图表，基于这些内容，FluxCD 将更新在集群中运行的工作负载。

1.  为了让 Flux 有实际操作的内容，我们需要创建 Flux 的实际清单。我们使用`HelmRelease` YAML 文件来实现，其格式如下：

helmrelease-1.yaml:

```
apiVersion: helm.fluxcd.io/v1
kind: HelmRelease
metadata:
  name: myapp
  annotations:
    fluxcd.io/automated: "true"
    fluxcd.io/tag.chart-image: glob:myapp-v*
spec:
  releaseName: myapp
  chart:
    git: ssh://git@github.com/<myuser>/<myinfrastructurerepository>/myhelmchart
    ref: master
    path: charts/myapp
  values:
    image:
      repository: myrepo/myapp
      tag: myapp-v2
```

让我们分析一下这个文件。我们正在指定 Flux 将在哪里找到我们应用程序的 Helm 图表的 Git 仓库。我们还使用`automated`注释标记`HelmRelease`，这告诉 Flux 每隔几分钟去轮询容器镜像仓库，看看是否有新版本需要部署。为了帮助这一点，我们包括了一个`chart-image`过滤模式，标记的容器镜像必须匹配才能触发重新部署。最后，在值部分，我们有 Helm 值，将用于 Helm 图表的初始安装。

为了向 FluxCD 提供这些信息，我们只需要将此文件添加到我们的 GitHub 仓库的根目录并推送更改。

一旦我们将这个发布文件`helmrelease-1.yaml`添加到我们的 Git 仓库中，Flux 将在几分钟内捕捉到它，然后查找`chart`值中指定的 Helm 图表。只有一个问题 - 我们还没有制作它！

目前，我们在 GitHub 上的基础设施仓库只包含我们的单个 Helm 发布文件。文件夹内容如下：

```
helmrelease1.yaml
```

为了闭环并允许 Flux 实际部署我们的 Helm 图表，我们需要将其添加到这个基础设施仓库中。让我们这样做，使我们 GitHub 仓库中的最终文件夹内容如下：

```
helmrelease1.yaml
myhelmchart/
  Chart.yaml
  Values.yaml
  Templates/
    … chart templates
```

现在，当 FluxCD 下次检查 GitHub 上的基础设施仓库时，它将首先找到 Helm 发布 YAML 文件，然后将其指向我们的新 Helm 图表。

有了新版本和 Helm 图表的 FluxCD，然后将我们的 Helm 图表部署到 Kubernetes！

然后，每当对 Helm 发布 YAML 或 Helm 图表中的任何文件进行更改时，FluxCD 将捕捉到，并在几分钟内（在其下一个循环中）部署更改。

此外，每当推送一个具有与过滤模式匹配的标签的新容器镜像到镜像仓库时，应用程序的新版本将自动部署 - 就是这么简单。这意味着 FluxCD 正在监听两个位置 - 基础设施 GitHub 仓库和容器仓库，并将部署对任一位置的任何更改。

您可以看到这如何映射到我们的集群外 CI/CD 实现，我们有一个 CodePipeline 来部署我们应用程序容器的新版本，另一个 CodePipeline 来部署对基础设施仓库的任何更改。FluxCD 以一种拉取方式做同样的事情。

# 总结

在本章中，我们学习了关于 Kubernetes 上的模板代码生成。我们回顾了如何使用 Helm 和 Kustomize 创建灵活的资源模板。有了这些知识，您将能够使用任一解决方案模板化您的复杂应用程序，创建或部署发布。然后，我们回顾了 Kubernetes 上的两种 CI/CD 类型；首先是通过 kubectl 将外部 CI/CD 部署到 Kubernetes，然后是使用 FluxCD 的集群内 CI 范例。有了这些工具和技术，您将能够为生产应用程序在 Kubernetes 上设置 CI/CD。

在下一章中，我们将回顾 Kubernetes 上的安全性和合规性，这是当今软件环境中的一个重要主题。

# 问题

1.  Helm 和 Kustomize 模板之间有哪两个区别？

1.  在使用外部 CI/CD 设置时，应如何处理 Kubernetes API 凭据？

1.  为什么在集群内设置 CI 可能比集群外设置更可取？反之呢？

# 进一步阅读

+   Kustomize 文档：https:[`kubernetes-sigs.github.io/kustomize/`](https://kubernetes-sigs.github.io/kustomize/)

+   Helm 文档[`docs.fluxcd.io/en/latest/tutorials/get-started-helm/`](https://docs.fluxcd.io/en/latest/tutorials/get-started-helm/)
