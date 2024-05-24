# Linux 架构实用手册（二）

> 原文：[`zh.annas-archive.org/md5/7D24F1F94933063822D38A8D8705DDE3`](https://zh.annas-archive.org/md5/7D24F1F94933063822D38A8D8705DDE3)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：理解 Kubernetes 集群的核心组件

在本章中，我们将从每个控制器的组成到如何部署和调度 pod 中的容器，对主要的 Kubernetes 组件进行一个全面的了解。了解 Kubernetes 集群的方方面面对于能够基于 Kubernetes 作为容器化应用程序的编排器部署和设计解决方案至关重要：

+   控制平面组件

+   Kubernetes 工作节点的组件

+   Pod 作为基本构建块

+   Kubernetes 服务、负载均衡器和 Ingress 控制器

+   Kubernetes 部署和 DaemonSets

+   Kubernetes 中的持久存储

# Kubernetes 控制平面

Kubernetes 主节点是核心控制平面服务所在的地方；并非所有服务都必须驻留在同一节点上；然而，出于集中和实用性的考虑，它们通常以这种方式部署。这显然引发了服务可用性的问题；然而，通过拥有多个节点并提供负载平衡请求，可以轻松克服这些问题，从而实现高度可用的**主节点**集。

主节点由四个基本服务组成：

+   kube-apiserver

+   kube-scheduler

+   kube-controller-manager

+   etcd 数据库

主节点可以在裸金属服务器、虚拟机或私有或公共云上运行，但不建议在其上运行容器工作负载。我们稍后会详细了解更多。

以下图表显示了 Kubernetes 主节点的组件：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-arch/img/7e921f9a-af2e-4baf-932e-7c58ac02a1ab.png)

# kube-apiserver

API 服务器是将所有内容联系在一起的东西。它是集群的前端 REST API，接收清单以创建、更新和删除诸如服务、pod、Ingress 等 API 对象。

**kube-apiserver**是我们应该与之交谈的唯一服务；它也是唯一一个写入并与`etcd`数据库交谈以注册集群状态的服务。通过`kubectl`命令，我们将发送命令与其交互。这将是我们在处理 Kubernetes 时的瑞士军刀。

# kube-controller-manager

**kube-controller-manager**守护程序，简而言之，是一组无限控制循环，以简单的单个二进制文件的形式进行交付。它监视集群的定义期望状态，并确保通过移动实现所需的所有组件来实现和满足它。kube-controller-manager 不仅仅是一个控制器；它包含了集群中监视不同组件的几个不同循环。其中一些是服务控制器、命名空间控制器、服务账户控制器等。您可以在 Kubernetes GitHub 存储库中找到每个控制器及其定义：

[`github.com/kubernetes/kubernetes/tree/master/pkg/controller`](https://github.com/kubernetes/kubernetes/tree/master/pkg/controller)。

# kube-scheduler

**kube-scheduler**将您新创建的 pod 调度到具有足够空间满足 pod 资源需求的节点上。它基本上监听 kube-apiserver 和 kube-controller-manager，以获取新创建的 pod，并将其放入队列，然后由调度程序安排到可用节点上。kube-scheduler 的定义可以在这里找到：

[`github.com/kubernetes/kubernetes/blob/master/pkg/scheduler`](https://github.com/kubernetes/kubernetes/blob/master/pkg/scheduler/scheduler.go)。

除了计算资源外，kube-scheduler 还会读取节点的亲和性和反亲和性规则，以确定节点是否能够运行该 pod。

# etcd 数据库

**etcd**数据库是一个非常可靠的一致性键值存储，用于存储 Kubernetes 集群的状态。它包含了节点正在运行的 pod 的当前状态，集群当前有多少个节点，这些节点的状态是什么，部署有多少个副本正在运行，服务名称等。

正如我们之前提到的，只有 kube-apiserver 与 etcd 数据库通信。如果 kube-controller-manager 需要检查集群的状态，它将通过 API 服务器获取 etcd 数据库的状态，而不是直接查询 etcd 存储。kube-scheduler 也是如此，如果调度程序需要通知某个 pod 已停止或分配到另一个节点，它将通知 API 服务器，API 服务器将在 etcd 数据库中存储当前状态。

通过 etcd，我们已经涵盖了 Kubernetes 主节点的所有主要组件，因此我们已经准备好管理我们的集群。但是，集群不仅由主节点组成；我们仍然需要执行重型工作并运行我们的应用程序的节点。

# Kubernetes 工作节点

在 Kubernetes 中执行此任务的工作节点简单地称为节点。在 2014 年左右，它们曾被称为 minions，但后来这个术语被替换为节点，因为这个名称与 Salt 的术语混淆，并让人们认为 Salt 在 Kubernetes 中扮演了重要角色。

这些节点是您将运行工作负载的唯一位置，因为不建议在主节点上运行容器或负载，因为它们需要可用于管理整个集群。

节点在组件方面非常简单；它们只需要三个服务来完成任务：

+   kubelet

+   kube-proxy

+   容器运行时

让我们更深入地探讨这三个组件。

# 容器运行时

为了能够启动容器，我们需要一个容器运行时。这是将在节点内核中为我们的 pod 创建容器的基本引擎。kubelet 将与此运行时进行通信，并根据需要启动或停止我们的容器。

目前，Kubernetes 支持任何符合 OCI 规范的容器运行时，例如 Docker、rkt、runc、runsc 等。

您可以从 OCI GitHub 页面了解有关所有规范的更多信息：[`github.com/opencontainers/runtime-spec`](https://github.com/opencontainers/runtime-spec)。

# kubelet

kubelet 是 Kubernetes 的一个低级组件，是继 kube-apiserver 之后最重要的组件之一；这两个组件对于在集群中提供 pod/容器至关重要。kubelet 是在 Kubernetes 节点上运行的一个服务，它监听 API 服务器以创建 pod。kubelet 只负责启动/停止并确保 pod 中的容器健康；kubelet 将无法管理未由其创建的任何容器。

kubelet 通过与容器运行时进行通信来实现目标，这是通过所谓的容器运行时接口（CRI）实现的。CRI 通过 gRPC 客户端为 kubelet 提供可插拔性，可以与不同的容器运行时进行通信。正如我们之前提到的，Kubernetes 支持多个容器运行时来部署容器，这就是它如何实现对不同引擎的多样化支持的方式。

您可以通过以下 GitHub 链接检查 kubelet 的源代码：[`github.com/kubernetes/kubernetes/tree/master/pkg/kubelet`](https://github.com/kubernetes/kubernetes/tree/master/pkg/kubelet)。

# kube-proxy

kube-proxy 是集群中每个节点上的一个服务，它使得 pod、容器和节点之间的通信成为可能。该服务监视 kube-apiserver 以获取定义的服务的更改（服务是 Kubernetes 中一种逻辑负载均衡器；我们将在本章后面更深入地了解服务），并通过 iptables 规则保持网络最新，以将流量转发到正确的端点。Kube-proxy 还在 iptables 中设置规则，对服务后面的 pod 进行随机负载平衡。

以下是 kube-proxy 创建的一个 iptables 规则的示例：

```
-A KUBE-SERVICES -d 10.0.162.61/32 -p tcp -m comment --comment "default/example: has no endpoints" -m tcp --dport 80 -j REJECT --reject-with icmp-port-unreachable
```

这是一个没有端点的服务（没有 pod 在其后面）。

现在我们已经了解了构成集群的所有核心组件，我们可以谈谈我们可以如何使用它们以及 Kubernetes 将如何帮助我们编排和管理我们的容器化应用程序。

# Kubernetes 对象

**Kubernetes 对象**就是这样：它们是逻辑持久对象或抽象，将代表您集群的状态。您负责告诉 Kubernetes 您对该对象的期望状态，以便它可以努力维护它并确保该对象存在。

要创建一个对象，它需要具备两个要素：状态和规范。状态由 Kubernetes 提供，并且它是对象的当前状态。Kubernetes 将根据需要管理和更新该状态，以符合您的期望状态。另一方面，`spec`字段是您提供给 Kubernetes 的内容，并且是您告诉它描述您所需对象的内容，例如，您希望容器运行的图像，您希望运行该图像的容器数量等。每个对象都有特定的`spec`字段，用于执行其任务类型，并且您将在发送到 kube-apiserver 的 YAML 文件中提供这些规范，该文件将使用`kubectl`将其转换为 JSON 并将其发送为 API 请求。我们将在本章后面更深入地了解每个对象及其规范字段。

以下是发送到`kubectl`的 YAML 的示例：

```
cat << EOF | kubectl create -f -
kind: Service
apiVersion: v1
metadata:
 Name: frontend-service
spec:
 selector:
   web: frontend
 ports:
 - protocol: TCP
   port: 80
   targetPort: 9256
EOF
```

对象定义的基本字段是最初的字段，这些字段不会因对象而异，并且非常直观。让我们快速浏览一下它们：

+   `kind`：`kind`字段告诉 Kubernetes 您正在定义的对象类型：pod、服务、部署等

+   `apiVersion`：因为 Kubernetes 支持多个 API 版本，我们需要指定一个 REST API 路径，以便将我们的定义发送到该路径

+   `metadata`：这是一个嵌套字段，这意味着您有更多的子字段可以写入 metadata，您可以在其中编写基本定义，例如对象的名称，将其分配给特定命名空间，并为其标记一个标签，以将您的对象与其他 Kubernetes 对象相关联

因此，我们现在已经了解了最常用的字段及其内容；您可以在以下 GitHub 页面了解有关 Kuberntes API 约定的更多信息：

[`github.com/kubernetes/community/blob/master/contributors/devel/api-conventions.md`](https://github.com/kubernetes/community/blob/master/contributors/devel/api-conventions.md)。

对象的某些字段在创建对象后可以进行修改，但这将取决于对象和您要修改的字段。

以下是您可以创建的各种 Kubernetes 对象的简短列表：

+   Pod

+   卷

+   服务

+   部署

+   入口

+   秘钥

+   配置映射

还有许多其他内容。

让我们更仔细地看看这些项目中的每一个。

# Pods - Kubernetes 的基础

Pod 是 Kubernetes 中最基本且最重要的对象。一切都围绕它们展开；我们可以说 Kubernetes 是为了 pod！所有其他对象都是为了服务它们，它们所做的所有任务都是为了使 pod 达到您期望的状态。

那么，什么是 pod，为什么 pod 如此重要？

Pod 是一个逻辑对象，在同一网络命名空间上运行一个或多个容器，相同的**进程间通信**（**IPC**），有时，根据 Kubernetes 的版本，还在相同的**进程 ID**（**PID**）命名空间上运行。这是因为它们将运行我们的容器，因此将成为关注的中心。Kubernetes 的整个目的是成为一个容器编排器，而通过 pod，我们使编排成为可能。

正如我们之前提到的，同一 pod 上的容器生活在一个“泡泡”中，它们可以通过 localhost 相互通信，因为它们彼此之间是本地的。一个 pod 中的一个容器与另一个容器具有相同的 IP 地址，因为它们共享网络命名空间，但在大多数情况下，您将以一对一的方式运行，也就是说，一个 pod 中只有一个容器。在非常特定的情况下才会在一个 pod 中运行多个容器，比如当一个应用程序需要一个数据推送器或需要以快速和有弹性的方式与主要应用程序通信的代理时。

定义 pod 的方式与定义任何其他 Kubernetes 对象的方式相同：通过包含所有 pod 规范和定义的 YAML：

```
kind: Pod
apiVersion: v1
metadata:
name: hello-pod
labels:
  hello: pod
spec:
  containers:
    - name: hello-container
      image: alpine
      args:
      - echo
      - "Hello World"
```

让我们来看看在`spec`字段下创建我们的 pod 所需的基本 pod 定义：

+   **容器：**容器是一个数组；因此，在它下面有一系列子字段。基本上，它定义了将在 pod 上运行的容器。我们可以为容器指定一个名称，要从中启动的图像，以及我们需要它运行的参数或命令。参数和命令之间的区别与我们在第六章中讨论的`CMD`和`ENTRYPOINT`的区别相同，当时我们讨论了创建 Docker 镜像。请注意，我们刚刚讨论的所有字段都是针对`containers`数组的。它们不是 pod 的`spec`的直接部分。

+   **restartPolicy:** 这个字段就是这样：它告诉 Kubernetes 如何处理容器，在零或非零退出代码的情况下，它适用于 pod 中的所有容器。您可以从 Never、OnFailure 或 Always 中选择。如果未定义 restartPolicy，Always 将是默认值。

这些是您将在 pod 上声明的最基本的规范；其他规范将要求您对如何使用它们以及它们如何与各种其他 Kubernetes 对象进行交互有更多的背景知识。我们将在本章后面重新讨论它们，其中一些如下：

+   卷

+   Env

+   端口

+   dnsPolicy

+   initContainers

+   nodeSelector

+   资源限制和请求

要查看当前在集群中运行的 pod，可以运行`kubectl get pods`：

```
dsala@MININT-IB3HUA8:~$ kubectl get pods
NAME      READY STATUS    RESTARTS AGE
busybox   1/1 Running   120 5d
```

或者，您可以运行`kubectl describe pods`，而不指定任何 pod。这将打印出集群中运行的每个 pod 的描述。在这种情况下，只会有`busybox` pod，因为它是当前唯一正在运行的 pod：

```
dsala@MININT-IB3HUA8:~$ kubectl describe pods
Name:               busybox
Namespace:          default
Priority:           0
PriorityClassName:  <none>
Node:               aks-agentpool-10515745-2/10.240.0.6
Start Time:         Wed, 19 Sep 2018 14:23:30 -0600
Labels:             <none>
Annotations:        <none>
Status:             Running
IP:                 10.244.1.7
Containers:
 busybox:
[...] (Output truncated for readability)
Events:
Type    Reason Age                 From      Message
----    ------ ----                ----      -------
Normal  Pulled 45s (x121 over 5d)  kubelet, aks-agentpool-10515745-2  Container image "busybox" already present on machine
Normal  Created 44s (x121 over 5d)  kubelet, aks-agentpool-10515745-2  Created container
Normal  Started 44s (x121 over 5d)  kubelet, aks-agentpool-10515745-2  Started container
```

Pods 是有生命期的，这是了解如何管理应用程序的关键。您必须明白，一旦 pod 死亡或被删除，就无法将其恢复。它的 IP 和在其上运行的容器将消失；它们是完全短暂的。作为卷挂载的 pod 上的数据可能会存活，也可能不会，这取决于您如何设置；然而，这是我们将在本章后面讨论的问题。如果我们的 pod 死亡并且我们失去它们，我们如何确保所有的微服务都在运行？嗯，部署就是答案。

# 部署

单独的 pod 并不是很有用，因为在单个 pod 中运行我们的应用程序的实例超过一个是不太有效率的。在没有一种方法来查找它们的情况下，在不同的 pod 上为我们的应用程序提供数百个副本将会很快失控。

这就是部署发挥作用的地方。通过部署，我们可以使用控制器来管理我们的 pod。这不仅允许我们决定要运行多少个，还可以通过更改容器正在运行的图像版本或图像本身来管理更新。部署是您大部分时间将要处理的内容。除了 pod 和我们之前提到的任何其他对象，它们在 YAML 文件中都有自己的定义：

```
apiVersion: apps/v1
kind: Deployment
metadata:
 name: nginx-deployment
 labels:
   deployment: nginx
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
       image: nginx:1.7.9
       ports:
       - containerPort: 80
```

让我们开始探索它们的定义。

在 YAML 的开头，我们有更一般的字段，如`apiVersion`，`kind`和`metadata`。但在`spec`下，我们将找到此 API 对象的特定选项。

在`spec`下，我们可以添加以下字段：

+   **选择器**：使用选择器字段，部署将知道在应用更改时要针对哪些 pod。在选择器下有两个字段：`matchLabels`和`matchExpressions`。使用`matchLabels`，选择器将使用 pod 的标签（键/值对）。重要的是要注意，您在这里指定的所有标签都将被`ANDed`。这意味着 pod 将要求具有您在`matchLabels`下指定的所有标签。`matchExpressions`很少使用，但您可以通过阅读我们在*进一步阅读*部分推荐的书籍来了解更多信息。

+   **副本**：这将说明部署需要通过复制控制器保持运行的 pod 数量；例如，如果指定了三个副本，并且其中一个 pod 死亡，复制控制器将监视副本规范作为期望的状态，并通知调度程序安排一个新的 pod，因为当前状态现在是 2，因为 pod 死亡。

+   **RevisionHistoryLimit**：每次对部署进行更改，此更改都将保存为部署的修订版本，您稍后可以恢复到以前的状态，或者保留更改的记录。您可以使用`kubectl` rollout history deployment/<部署名称>来查看历史记录。使用`revisionHistoryLimit`，您可以设置一个数字，指定要保存多少条记录。

+   **策略**：这将让您决定如何处理任何更新或水平 pod 扩展。要覆盖默认值（即`rollingUpdate`），您需要编写`type`键，您可以在两个值之间进行选择：`recreate`或`rollingUpdate`。虽然`recreate`是更新部署的快速方式，它将删除所有 pod 并用新的替换它们，但这意味着您必须考虑到这种策略将导致系统停机。另一方面，`rollingUpdate`更加平稳和缓慢，非常适合可以重新平衡其数据的有状态应用程序。`rollingUpdate`为另外两个字段打开了大门，这些字段是`maxSurge`和`maxUnavailable`。第一个字段将是在执行更新时您希望超出总数的 pod 数量；例如，具有 100 个 pod 和 20%`maxSurge`的部署将在更新时增长到最多 120 个 pod。下一个选项将让您选择在 100 个 pod 场景中愿意杀死多少百分比的 pod 以用新的替换它们。在存在 20%`maxUnavailable`的情况下，只有 20 个 pod 将被杀死并用新的替换，然后继续替换部署的其余部分。

+   **模板**：这只是一个嵌套的 pod spec 字段，您将在其中包含部署将要管理的 pod 的所有规范和元数据。

我们已经看到，通过部署，我们管理我们的 pod，并帮助我们将它们保持在我们期望的状态。所有这些 pod 仍然处于所谓的**集群网络**中，这是一个封闭的网络，其中只有 Kubernetes 集群组件可以相互通信，甚至有自己的一组 IP 范围。我们如何从外部与我们的 pod 通信？我们如何访问我们的应用程序？这就是服务发挥作用的地方。

# 服务

名称*service*并不能完全描述 Kubernetes 中服务的实际作用。Kubernetes 服务是将流量路由到我们的 pod 的东西。我们可以说服务是将 pod 联系在一起的东西。

假设我们有一个典型的前端/后端类型的应用程序，其中我们的前端 pod 通过 pod 的 IP 地址与我们的后端 pod 进行通信。如果后端的 pod 死掉，我们知道 pod 是短暂的，因此我们失去了与后端的通信，现在我们陷入了困境。这不仅是因为新的 pod 将不具有与死掉的 pod 相同的 IP 地址，而且现在我们还必须重新配置我们的应用程序以使用新的 IP 地址。这个问题和类似的问题都可以通过服务来解决。

服务是一个逻辑对象，告诉 kube-proxy 根据服务后面的哪些 pod 创建 iptables 规则。服务配置它们的端点，这是服务后面的 pod 的称呼方式，与部署了解要控制哪些 pod 一样，选择器字段和 pod 的标签。

这张图展示了服务如何使用标签来管理流量：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-arch/img/1a03e05d-be3b-4a05-a7ff-7808314eb329.png)

服务不仅会让 kube-proxy 创建路由流量的规则；它还会触发一些称为**kube-dns**的东西。

Kube-dns 是一组在集群上运行的`SkyDNS`容器的 pod，提供 DNS 服务器和转发器，它将为服务和有时为了方便使用而创建的 pod 创建记录。每当您创建一个服务时，将创建一个指向服务内部集群 IP 地址的 DNS 记录，形式为`service-name.namespace.svc.cluster.local`。您可以在 Kubernetes GitHub 页面上了解更多关于 Kubernetes DNS 规范的信息：[`github.com/kubernetes/dns/blob/master/docs/specification.md`](https://github.com/kubernetes/dns/blob/master/docs/specification.md)。

回到我们的例子，现在我们只需要配置我们的应用程序以与服务的**完全合格的域名**（**FQDN**）通信，以便与我们的后端 pod 通信。这样，无论 pod 和服务具有什么 IP 地址都无关紧要。如果服务后面的 pod 死掉，服务将通过使用 A 记录来处理一切，因为我们将能够告诉我们的前端将所有流量路由到 my-svc。服务的逻辑将处理其他一切。

在声明要在 Kubernetes 中创建的对象时，您可以创建几种类型的服务。让我们逐个了解它们，看看哪种类型最适合我们需要的工作：

+   **ClusterIP**：这是默认服务。每当您创建 ClusterIP 服务时，它将创建一个仅在 Kubernetes 集群内可路由的集群内部 IP 地址的服务。这种类型非常适合只需要彼此交谈而不需要离开集群的 pod。

+   **NodePort**：当您创建这种类型的服务时，默认情况下将分配一个从`30000`到`32767`的随机端口来转发流量到服务的端点 pod。您可以通过在`ports`数组中指定节点端口来覆盖此行为。一旦定义了这一点，您将能够通过`<Nodes-IP>`:`<Node-Port>`访问您的 pod。这对于通过节点 IP 地址从集群外部访问您的 pod 非常有用。

+   **LoadBalancer**：大多数情况下，您将在云提供商上运行 Kubernetes。在这些情况下，LoadBalancer 类型非常理想，因为您将能够通过云提供商的 API 为您的服务分配公共 IP 地址。这是当您想要与集群外部的 pod 通信时的理想服务。使用 LoadBalancer，您不仅可以分配公共 IP 地址，还可以使用 Azure 从您的虚拟专用网络中分配私有 IP 地址。因此，您可以从互联网或在您的私有子网上内部与您的 pod 通信。

让我们回顾一下服务的 YAML 定义：

```
apiVersion: v1
kind: Service
metadata:  
 name: my-service
spec:
 selector:    
   app: front-end
 type: NodePort
 ports:  
 - name: http
   port: 80
   targetPort: 8080
   nodePort: 30024
   protocol: TCP
```

服务的 YAML 非常简单，规范会有所不同，取决于您正在创建的服务类型。但您必须考虑的最重要的事情是端口定义。让我们来看看这些：

+   `port`：这是暴露的服务端口

+   `targetPort`：这是服务发送流量到 Pod 的端口

+   `nodePort`：这是将被暴露的端口。

虽然我们现在了解了如何与集群中的 Pods 进行通信，但我们仍然需要了解每次 Pod 终止时我们如何管理丢失数据的问题。这就是**持久卷**（**PV**）发挥作用的地方。

# Kubernetes 和持久存储

在容器世界中，**持久存储**是一个严重的问题。当我们学习 Docker 镜像时，我们了解到唯一持久跨容器运行的存储是镜像的层，而且它们是只读的。容器运行的层是读/写的，但当容器停止时，该层中的所有数据都会被删除。对于 Pods 来说也是一样的。当容器死掉时，写入其中的数据也会消失。

Kubernetes 有一组对象来处理跨 Pod 的存储。我们将讨论的第一个对象是卷。

# 卷

**卷**解决了持久存储时的最大问题之一。首先，卷实际上不是对象，而是 Pod 规范的定义。当您创建一个 Pod 时，您可以在 Pod 规范字段下定义一个卷。此 Pod 中的容器将能够在其挂载命名空间上挂载卷，并且卷将在容器重新启动或崩溃时可用。但是，卷与 Pod 绑定，如果删除 Pod，卷也将消失。卷上的数据是另一回事；数据持久性将取决于该卷的后端。

Kubernetes 支持多种类型的卷或卷源以及它们在 API 规范中的称呼，这些类型包括来自本地节点的文件系统映射、云提供商的虚拟磁盘以及软件定义的存储支持的卷。当涉及到常规卷时，本地文件系统挂载是最常见的。需要注意的是使用本地节点文件系统的缺点是数据将不会在集群的所有节点上可用，而只在调度 Pod 的节点上可用。

让我们来看一下如何在 YAML 中定义一个带有卷的 Pod：

```
apiVersion: v1
kind: Pod
metadata:
 name: test-pd
spec:
 containers:
 - image: k8s.gcr.io/test-webserver
   name: test-container
   volumeMounts:
   - mountPath: /test-pd
     name: test-volume
 volumes:
 - name: test-volume
   hostPath:
     path: /data
   type: Directory
```

请注意`spec`下有一个名为`volumes`的字段，然后另一个名为`volumeMounts`。

第一个字段（`volumes`）是您为该 Pod 定义要创建的卷的位置。该字段将始终需要一个名称，然后是一个卷源。根据源的不同，要求也会有所不同。在这个例子中，源将是`hostPath`，这是节点的本地文件系统。`hostPath`支持多种类型的映射，从目录、文件、块设备，甚至 Unix 套接字。

在第二个字段`volumeMounts`下，我们有`mountPath`，这是您在容器内定义要将卷挂载到的路径。`name`参数是您指定给 Pod 要使用哪个卷的方式。这很重要，因为您可以在`volumes`下定义多种类型的卷，而名称将是 Pod 知道哪些卷挂载到哪个容器的唯一方式。

我们不会详细介绍所有不同类型的卷，因为除非你要使用特定的卷，否则了解它们是无关紧要的。重要的是要知道它们的存在以及我们可以拥有什么类型的来源。

您可以在 Kubernetes 网站的卷定义中了解更多关于不同类型的卷（[`kubernetes.io/docs/concepts/storage/volumes/#types-of-volumes`](https://kubernetes.io/docs/concepts/storage/volumes/#types-of-volumes)）以及 Kubernetes API 参考文档中的卷定义（[`kubernetes.io/docs/reference/generated/kubernetes-api/v1.11/#volume-v1-core`](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.11/#volume-v1-core)）。

让卷随 Pod 一起消失并不理想。我们需要持久存储，这就是 PV 的需求产生的原因。

# 持久卷、持久卷索赔和存储类别

卷和 PV 之间的主要区别在于，与卷不同，PV 实际上是 Kubernetes API 对象，因此您可以像单独的实体一样单独管理它们，因此它们甚至在删除 pod 后仍然存在。

您可能想知道为什么这个小节中混合了 PV、持久卷索赔（PVC）和存储类别。这是因为我们不能谈论其中一个而不谈论其他；它们都彼此依赖，了解它们如何相互作用以为我们的 pod 提供存储是至关重要的。

让我们从 PV 和 PVC 开始。与卷一样，PV 具有存储源，因此卷具有的相同机制在这里也适用。您可以有一个软件定义的存储集群提供**逻辑单元号**（**LUNs**），云提供商提供虚拟磁盘，甚至是本地文件系统提供给 Kubernetes 节点，但是这里，它们被称为**持久卷类型**而不是卷源。

PV 基本上就像存储阵列中的 LUN：您创建它们，但没有映射；它们只是一堆已分配的存储，等待使用。这就是 PVC 发挥作用的地方。PVC 就像 LUN 映射：它们支持或绑定到 PV，也是您实际定义、关联和提供给 pod 以供其容器使用的东西。

您在 pod 上使用 PVC 的方式与普通卷完全相同。您有两个字段：一个用于指定要使用的 PVC，另一个用于告诉 pod 要在哪个容器上使用该 PVC。

PVC API 对象定义的 YAML 应该包含以下代码：

```
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
 name: gluster-pvc  
spec:
 accessModes:
 - ReadWriteMany      
 resources:
    requests:
      storage: 1Gi    
```

`pod`的 YAML 应该包含以下代码：

```
kind: Pod
apiVersion: v1
metadata:
 name: mypod
spec:
 containers:
   - name: myfrontend
     image: nginx
     volumeMounts:
     - mountPath: "/mnt/gluster"
       name: volume
 volumes:
   - name: volume
     persistentVolumeClaim:
       claimName: gluster-pvc
```

当 Kubernetes 管理员创建 PVC 时，有两种方式可以满足此请求：

+   **静态**：已经创建了几个 PV，然后当用户创建 PVC 时，可以满足要求的任何可用 PV 都将绑定到该 PVC。

+   **动态**：某些 PV 类型可以根据 PVC 定义创建 PV。创建 PVC 时，PV 类型将动态创建 PV 对象并在后端分配存储；这就是动态配置。动态配置的关键在于您需要第三种 Kubernetes 存储对象，称为**存储类别**。

存储类别就像是对存储进行**分层**的一种方式。您可以创建一个类别，用于提供慢速存储卷，或者另一个类别，其中包含超快速 SSD 驱动器。但是，存储类别比仅仅分层要复杂一些。正如我们在创建 PVC 的两种方式中提到的，存储类别是使动态配置成为可能的关键。在云环境中工作时，您不希望手动为每个 PV 创建每个后端磁盘。存储类别将设置一个称为**提供程序**的东西，它调用必要的卷插件以与您的云提供商的 API 进行通信。每个提供程序都有自己的设置，以便它可以与指定的云提供商或存储提供商进行通信。

您可以按以下方式配置存储类别；这是一个使用 Azure-disk 作为磁盘提供程序的存储类别的示例：

```
kind: StorageClass
apiVersion: storage.k8s.io/v1
metadata:
 name: my-storage-class
provisioner: kubernetes.io/azure-disk
parameters:
 storageaccounttype: Standard_LRS
 kind: Shared
```

每个存储类别的提供程序和 PV 类型都有不同的要求和参数，以及卷，我们已经对它们的工作原理和用途有了一个总体概述。了解特定的存储类别和 PV 类型将取决于您的环境；您可以通过点击以下链接了解它们中的每一个：

+   [`kubernetes.io/docs/concepts/storage/storage-classes/#provisioner`](https://kubernetes.io/docs/concepts/storage/storage-classes/#provisioner)

+   [`kubernetes.io/docs/concepts/storage/persistent-volumes/#types-of-persistent-volumes`](https://kubernetes.io/docs/concepts/storage/persistent-volumes/#types-of-persistent-volumes)

# 摘要

在本章中，我们了解了 Kubernetes 是什么，它的组件，以及使用编排的优势。

现在，您应该能够识别每个 Kubernetes API 对象，它们的目的和用例。您应该能够理解主节点如何控制集群以及工作节点中容器的调度。

# 问题

1.  什么是 Kubernetes？

1.  Kubernetes 的组件是什么？

1.  Kubernetes 的 API 对象是什么？

1.  我们可以用 Kubernetes 做什么？

1.  什么是容器编排器？

1.  什么是 Pod？

1.  什么是部署？

# 进一步阅读

+   *精通 Kubernetes*，由 Packt Publishing 出版：[`prod.packtpub.com/in/virtualization-and-cloud/mastering-kubernetes`](https://prod.packtpub.com/in/virtualization-and-cloud/mastering-kubernetes)

+   *面向开发人员的 Kubernetes*，由 Packt Publishing 出版：[`prod.packtpub.com/in/virtualization-and-cloud/kubernetes-developers`](https://prod.packtpub.com/in/virtualization-and-cloud/kubernetes-developers)

+   *开始使用 Kubernetes*，由 Packt Publishing 出版：[`prod.packtpub.com/in/virtualization-and-cloud/getting-started-kubernetes-third-edition`](https://prod.packtpub.com/in/virtualization-and-cloud/getting-started-kubernetes-third-edition)


# 第八章：设计 Kubernetes 集群

现在我们了解了组成 Kubernetes 集群的基础知识，我们仍然需要了解如何将所有 Kubernetes 组件放在一起，以及如何满足它们的要求来提供一个可用于生产的 Kubernetes 集群。

在这一章中，我们将研究如何确定这些要求以及它们将如何帮助我们维持稳定的工作负载并实现成功的部署。

在本章中，我们将探讨以下主题：

+   Kube-sizing

+   确定存储考虑因素

+   确定网络要求

+   自定义 kube 对象

# Kube-sizing

在设计 Kubernetes 集群时，我们不仅需要担心如何配置部署对象来托管我们的应用程序，或者如何配置服务对象来提供跨我们的 pod 的通信，还需要考虑托管所有这些的位置。因此，我们还需要考虑所需的资源，以平衡我们的应用程序工作负载和控制平面。

# etcd 考虑因素

我们将需要至少一个三节点的 `etcd` 集群，以便在一个节点失败的情况下能够支持自身。因为 `etcd` 使用一种称为 **Raft** 的分布式普查算法，所以建议使用奇数个集群。这是因为，为了允许某个操作，集群的成员超过 50% 必须同意。例如，在一个两节点集群的情况下，如果其中一个节点失败，另一个节点的投票只占集群的 50%，因此，集群失去了法定人数。现在，当我们有一个三节点集群时，单个节点的故障只代表了 33.33% 的投票损失，而剩下的两个节点的投票仍然占 66.66%，以允许该操作。

以下链接是一个很棒的网站，您可以在其中学习 Raft 算法的工作原理：[`thesecretlivesofdata.com/raft/`](http://thesecretlivesofdata.com/raft/)。

对于 `etcd`，我们可以为我们的集群选择两种部署模型。我们可以将其运行在与我们的 kube-apiserver 相同的节点上，或者我们可以有一组单独的集群来运行我们的键值存储。无论哪种方式，这都不会改变 `etcd` 如何达成法定人数，因此您仍然需要在控制平面管理节点上安装奇数个 `etcd`。

对于 Kubernetes 的使用情况，`etcd` 不会消耗大量的计算资源，如 CPU 或内存。尽管 `etcd` 会积极地缓存键值数据并使用大部分内存来跟踪观察者，但两个核心和 8 GB 的内存将是绰绰有余的。

当涉及到磁盘时，这就需要更加严格。`etcd` 集群严重依赖磁盘延迟，因为共识协议以日志的方式持久存储元数据。`etcd` 集群的每个成员都必须存储每个请求，任何延迟的重大波动都可能触发集群领导者选举，这将导致集群不稳定。`etcd` 的 **硬盘驱动器**（**HDD**）是不可能的，除非您在 Raid 0 磁盘上运行 15k RPM 磁盘以从磁性驱动器中挤出最高性能。**固态硬盘**（**SSD**）是最佳选择，具有极低的延迟和更高的 **每秒输入/输出操作**（**IOPS**），它们是托管您的键值存储的理想候选者。值得庆幸的是，所有主要的云提供商都提供 SSD 解决方案来满足这种需求。

# kube-apiserver 大小

控制平面组件所需的剩余资源将取决于它们将管理的节点数量以及您将在其上运行的附加组件。需要考虑的另一件事是，您可以将这些主节点放在负载均衡器后面，以减轻负载并提供高可用性。此外，您还可以在争用期间始终水平扩展您的主节点。

考虑到所有这些，并考虑到`etcd`将与我们的主节点一起托管，我们可以说，具有 2 到 4 个 vCPU 和 8 到 16 GB RAM 的**虚拟机**（**VMs**）的三个主节点集群将足以处理大于或等于 100 个工作节点。

# 工作节点

另一方面，工作节点将承担繁重的工作——这些节点将运行我们的应用工作负载。标准化这些节点的大小将是不可能的，因为它们属于*假设发生什么*的情景。我们需要确切地知道我们将在节点上运行什么类型的应用程序，以及它们的资源需求，以便我们能够正确地对其进行规模化。节点不仅将根据应用程序的资源需求进行规模化，而且我们还必须考虑在其中运行超过我们计划的 pod 的时期。例如，您可以对部署执行滚动更新以使用新的镜像，具体取决于您如何配置您的`maxSurge`；这个节点将不得不处理 10%到 25%的额外负载。

容器非常轻量级，但当编排器开始运行时，您可以在单个节点上运行 30、40 甚至 100 个容器！这会大幅增加每个主机的资源消耗。虽然 pod 具有资源限制功能和规范来限制容器的资源消耗，但您仍然需要考虑这些容器所需的资源。

在资源需求高和争用期间，节点始终可以进行水平扩展。然而，始终可以使用额外的资源来避免任何不良的**内存不足**（**OOMs**）杀手。因此，通过拥有额外的资源池来规划未来和*假设发生什么*的情景。

# 负载均衡器考虑

我们的节点仍然需要与我们的 API 服务器通信，并且正如我们之前提到的，拥有多个主节点需要一个负载均衡器。当涉及到从我们的节点到主节点的负载均衡请求时，我们有几个选项可供选择，具体取决于您运行集群的位置。如果您在公共云中运行 Kubernetes，可以选择使用云提供商的负载均衡器选项，因为它们通常是弹性的。这意味着它们会根据需要自动扩展，并提供比您实际需要的更多功能。基本上，负载均衡请求到 API 服务器将是负载均衡器执行的唯一任务。这将导致我们的场景——因为我们在这里坚持使用开源解决方案，所以您可以配置运行 HAProxy 或 NGINX 的 Linux 框来满足您的负载均衡需求。在选择 HAProxy 和 NGINX 之间没有错误答案，因为它们提供了您所需的功能。

到目前为止，基本架构将如下截图所示：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-arch/img/ae11e5e7-863f-4eb1-aaab-b5be6cdd8b81.png)

# 存储考虑

存储需求并不像常规主机或虚拟化程序那样直截了当。我们的节点和 pod 将使用几种类型的存储，我们需要适当地对它们进行分层。由于您正在运行 Linux，将存储分层到不同的文件系统和存储后端将非常容易——没有**逻辑卷管理器**（**LVM**）或不同的挂载点无法解决的问题。

基本的 Kubernetes 二进制文件，如`kubelet`和`kube-proxy`，可以在基本存储上运行，与操作系统文件一起；不需要非常高端的存储，任何 SSD 都足以满足它们的需求。

另一方面，我们有存储，容器镜像将存储和运行。回到[第六章]（6da53f60-978c-43a4-9dc9-f16b14405709.xhtml），*创建高可用的自愈架构*，我们了解到容器由只读层组成。这意味着当磁盘在单个节点上运行数十甚至数百个容器时，它们将受到读取请求的严重打击。用于此的存储后端将必须以非常低的延迟提供读取请求。在 IOPS 和延迟方面的具体数字将因环境而异，但基础将是相同的。这是因为容器的性质——提供更高读取性能而非写入的磁盘将更可取。

存储性能并不是唯一需要考虑的因素。存储空间也非常重要。计算所需空间将取决于以下两个因素：

1.  你将要运行的镜像有多大？

1.  你将运行多少不同的镜像，它们的大小是多少？

这将直接消耗`/var/lib/docker`或`/var/lib/containerd`中的空间。考虑到这一点，为`/var/lib/docker`或`containerd/`设置一个单独的挂载点，具有足够的空间来存储你将在 pod 上运行的所有镜像，将是一个不错的选择。请注意，这些镜像是临时的，不会永远存在于你的节点上。Kubernetes 确实在 kubelet 中嵌入了垃圾收集策略，当达到指定的磁盘使用阈值时，将删除不再使用的旧镜像。这些选项是`HighThresholdPercent`和`LowThresholdPercent`。你可以使用 kubelet 标志进行设置：`--eviction-hard=imagefs.available`或`--eviction-soft=imagefs.available`。这些标志已经默认配置为在可用存储空间低于 15%时进行垃圾收集，但是你可以根据需要进行调整。`eviction-hard`是需要达到的阈值，以开始删除镜像，而`eviction-soft`是需要达到的百分比或数量，以停止删除镜像。

一些容器仍将需要某种读/写卷以用于持久数据。如[第七章]（d89f650b-f4ea-4cda-9111-a6e6fa6c2256.xhtml）中所讨论的，Kubernetes 集群的核心组件，有几种存储供应商，它们都适用于不同的场景。你需要知道的是，由于 Kubernetes 存储类别的存在，你有一系列可用的选项。以下是一些值得一提的开源软件定义存储解决方案：

+   Ceph

+   GlusterFS

+   OpenStack Cinder

+   **网络文件系统**（**NFS**）

每个存储供应商都有其优势和劣势，但详细介绍每个存储供应商已超出了本书的范围。我们在之前的章节中对 Gluster 进行了很好的概述，因为在后续章节中我们将用它来进行示例部署。

# 网络要求

为了了解我们集群的网络要求，我们首先需要了解 Kubernetes 网络模型以及它旨在解决的问题。容器网络可能很难理解；然而，它有三个基本问题：

1.  容器如何相互通信（在同一台主机上和在不同的主机上）？

1.  容器如何与外部世界通信，外部世界如何与容器通信？

1.  谁分配和配置每个容器的唯一 IP 地址？

同一主机上的容器可以通过虚拟桥相互通信，您可以使用`bridge-utils`软件包中的`brctl`实用程序看到这一点。这由 Docker 引擎处理，称为 Docker 网络模型。容器通过分配 IP 来附加到名为`docker0`的虚拟桥上的`veth`虚拟接口。这样，所有容器都可以通过它们的`veth`虚拟接口相互通信。Docker 模型的问题出现在容器分配在不同主机上，或者外部服务想要与它们通信时。为解决这个问题，Docker 提供了一种方法，其中容器通过主机的端口暴露给外部世界。请求进入主机 IP 地址的某个端口，然后被代理到该端口后面的容器。

这种方法很有用，但并非理想。您无法将服务配置为特定端口或在动态端口分配方案中—我们的服务将需要标志每次部署时连接到正确的端口。这可能会很快变得非常混乱。

为了避免这种情况，Kubernetes 实现了自己的网络模型，必须符合以下规则：

1.  所有 pod 可以在没有网络地址转换（NAT）的情况下与所有其他 pod 通信

1.  所有节点可以在没有 NAT 的情况下与所有 pod 通信

1.  pod 看到的 IP 与其他人看到的 IP 相同

有几个开源项目可以帮助我们实现这个目标，最适合您的项目将取决于您的情况。以下是其中一些：

+   Project Calico

+   Weave Net

+   Flannel

+   Kube-router

为 pod 分配 IP 并使它们相互通信并不是唯一需要注意的问题。Kubernetes 还提供基于 DNS 的服务发现，因为通过 DNS 记录而不是 IP 进行通信的应用程序更有效和可扩展。

# 基于 Kubernetes 的 DNS 服务发现

Kubernetes 在其 kube-system 命名空间中部署了一个部署，我们将在本章后面重新讨论命名空间。该部署由一个包含一组容器的 pod 组成，形成一个负责在集群中创建所有 DNS 记录并为服务发现提供 DNS 请求的 DNS 服务器。

Kubernetes 还将创建一个指向上述部署的服务，并告诉 kubelet 默认配置每个 pod 的容器使用服务的 IP 作为 DNS 解析器。这是默认行为，但您可以通过在 pod 规范上设置 DNS 策略来覆盖此行为。您可以从以下规范中进行选择：

+   **默认**：这个是反直觉的，因为实际上并不是默认的。使用此策略，pod 将继承运行该 pod 的节点的名称解析。例如，如果一个节点配置为使用`8.8.8.8`作为其 DNS 服务器，那么`resolv.conf`中的 pod 也将被配置为使用相同的 DNS 服务器。

+   **ClusterFirst**：这实际上是默认策略，正如我们之前提到的，任何使用 ClusterFirst 运行的 pod 都将使用`kube-dns`服务的 IP 配置`resolv.conf`。不是本地集群的任何请求都将转发到节点配置的 DNS 服务器。

并非所有 Kubernetes 对象都具有 DNS 记录。只有服务和在某些特定情况下，pod 才会为它们创建记录。DNS 服务器中有两种类型的记录：**A 记录**和**服务记录**（**SRV**）。A 记录是根据创建的服务类型创建的；我们这里指的不是`spec.type`。有两种类型的服务：**普通服务**，我们在第七章中进行了修订，*理解 Kubernetes 集群的核心组件*，并对应于`type`规范下的服务；和**无头服务**。在解释无头服务之前，让我们探讨普通服务的行为。

对于每个普通服务，将创建指向服务的集群 IP 地址的 A 记录；这些记录的结构如下：

```
<service-name>.<namespace>.svc.cluster.local
```

与服务运行在相同命名空间的任何 pod 都可以通过其`shortname: <service-name>`字段解析服务。这是因为命名空间之外的任何其他 pod 都必须在 shortname 实例之后指定命名空间：

```
<service-name>.<namespace>
```

对于无头服务，记录的工作方式有些不同。首先，无头服务是一个没有分配集群 IP 的服务。因此，无法创建指向服务 IP 的 A 记录。要创建无头服务，您以这种方式定义`.spec.clusterIP`命名空间为`none`，以便不为其分配 IP。然后，Kubernetes 将根据此服务的端点创建 A 记录。基本上，通过`selector`字段选择 pod，尽管这不是唯一的要求。由于 A 记录的创建格式，pod 需要几个新字段，以便 DNS 服务器为它们创建记录。

Pods 将需要两个新的规范字段：`hostname`和`subdomain`。`hostname`字段将是 pod 的`hostname`字段，而`subdomain`将是您为这些 pod 创建的无头服务的名称。这将指向每个 pod 的 IP 的 A 记录如下：

```
<pod hostname>.<subdomian/headless service name>.<namespace>.svc.cluster.local
```

此外，将创建另一个仅包含无头服务的记录，如下所示：

```
<headless service>.<namespace>.svc.cluster.local
```

此记录将返回服务后面所有 pod 的 IP 地址。

我们现在已经有了开始构建我们的集群所需的东西。但是，还有一些设计特性不仅包括 Kubernetes 二进制文件及其配置，还可以调整 Kubernetes API 对象。我们将在下一节中介绍一些您可以执行的调整。

# 自定义 kube 对象

在涉及 Kubernetes 对象时，一切都将取决于您尝试为其构建基础架构的工作负载或应用程序的类型。因此，与其设计或构建任何特定的自定义，我们将介绍如何在每个对象上配置最常用和有用的规范。

# 命名空间

Kubernetes 提供命名空间作为将集群分割成多个**虚拟集群**的一种方式。将其视为一种将集群资源和对象进行分割并使它们在逻辑上相互隔离的方式。

命名空间只会在非常特定的情况下使用，但 Kubernetes 带有一些预定义的命名空间：

+   **默认**：这是所有没有命名空间定义的对象将放置在其中的默认命名空间。

+   **kube-system**：由 Kubernetes 集群创建的和为其创建的任何对象都将放置在此命名空间中。用于集群基本功能的必需对象将放置在这里。例如，您将找到`kube-dns`，`kubernetes-dashboard`，`kube-proxy`或任何外部应用程序的其他组件或代理，例如`fluentd`，`logstash`，`traefik`和入口控制器。

+   **kube-public**：为任何人可见的对象保留的命名空间，包括非经过身份验证的用户。

创建命名空间非常简单直接；您可以通过运行以下命令来执行：

```
kubectl create namespace <name>
```

就是这样——现在您有了自己的命名空间。要将对象放置在此命名空间中，您将使用`metadata`字段并添加`namespace`键值对；例如，考虑来自 YAML pod 的这段摘录：

```
    apiVersion: v1
    kind: Pod
    metadata:
        namespace: mynamespace
        name: pod1    
```

您将发现自己为通常非常庞大并且有相当数量的用户或不同团队在使用资源的集群创建自定义命名空间。对于这些类型的场景，命名空间非常完美。命名空间将允许您将一个团队的所有对象与其余对象隔离开来。名称甚至可以在相同的类对象上重复，只要它们在不同的命名空间中。

命名空间不仅为对象提供隔离，还可以为每个命名空间设置资源配额。假设您有几个开发团队在集群上工作——一个团队正在开发一个非常轻量级的应用程序，另一个团队正在开发一个非常占用资源的应用程序。在这种情况下，您不希望第一个开发团队从资源密集型应用程序团队那里消耗任何额外的计算资源——这就是资源配额发挥作用的地方。

# 限制命名空间资源

资源配额也是 Kubernetes API 对象；但是，它们被设计为专门在命名空间上工作，通过在每个分配的空间上创建计算资源的限制，甚至限制对象的数量。

`ResourceQuota` API 对象与 Kubernetes 中的任何其他对象一样，通过传递给`kubectl`命令的`YAML`文件声明。

基本资源配额定义如下：

```
apiVersion: v1
kind: ResourceQuota
Metadata:
  Namespace: devteam1 
  name: compute-resources
spec:
  hard:
    pods: "4"
    requests.cpu: "1"
    requests.memory: 1Gi
    limits.cpu: "2"
    limits.memory: 2Gi
```

我们可以设置两种基本配额：计算资源配额和对象资源配额。如前面的例子所示，`pods`是对象配额，其余是计算配额。

在这些领域中，您将指定提供的资源的总和，命名空间不能超过。例如，在此命名空间中，运行的`pods`的总数不能超过`4`，它们的资源总和不能超过`1`个 CPU 和`2Gi` RAM 内存。

可以为任何可以放入命名空间的 kube API 对象分配的每个命名空间的最大对象数；以下是可以使用命名空间限制的对象列表：

+   **持久卷索赔**（**PVCs**）

+   服务

+   秘密

+   配置映射

+   复制控制器

+   部署

+   副本集

+   有状态集

+   作业

+   定期作业

在计算资源方面，不仅可以限制内存和 CPU，还可以为存储空间分配配额——但是这些配额仅适用于 PVCs。

为了更好地理解计算配额，我们需要更深入地了解这些资源是如何在 pod 基础上管理和分配的。这也是一个很好的时机来了解如何更好地设计 pod。

# 自定义 pod

在非受限命名空间上没有资源限制的 pod 可以消耗节点的所有资源而不受警告；但是，您可以在 pod 的规范中使用一组工具来更好地处理它们的计算分配。

当您为 pod 分配资源时，实际上并不是将它们分配给 pod。相反，您是在容器基础上进行分配。因此，具有多个容器的 pod 将为其每个容器设置多个资源约束；让我们考虑以下示例：

```
apiVersion: v1
 kind: Pod
 metadata:
  name: frontend
 spec:
  containers:
  - name: db
    image: mysql
    env:
    - name: MYSQL_ROOT_PASSWORD
      value: "password"
    resources:
      requests:
        memory: "64Mi"
        cpu: "250m"
      limits:
        memory: "128Mi"
        cpu: "500m"
  - name: wp
    image: wordpress
    resources:
      requests:
        memory: "64Mi"
        cpu: "250m"
      limits:
        memory: "128Mi"
        cpu: "500m"
```

在此 pod 声明中，在`containers`定义下，我们有两个尚未涵盖的新字段：`env`和`resources`。`resources`字段包含我们的`containers`的计算资源限制和要求。通过设置`limits`，您告诉容器它可以要求该资源类型的最大资源数量。如果容器超过限制，将重新启动或终止。

`request`字段指的是 Kubernetes 将向该容器保证的资源量。为了使容器能够运行，主机节点必须有足够的空闲资源来满足请求。

CPU 和内存以不同的方式进行测量。例如，当我们分配或限制 CPU 时，我们使用 CPU 单位进行讨论。设置 CPU 单位有几种方法；首先，您可以指定圆整或分数，例如 1、2、3、0.1 和 1.5，这将对应于您要分配给该容器的虚拟核心数。另一种分配的方法是使用**milicore**表达式。一个 milicore（1m），是您可以分配的最小 CPU 数量，相当于 0.001 CPU 核心；例如，您可以进行以下分配：

```
cpu: "250m"
```

这将与编写以下内容相同：

```
cpu: 0.25
```

分配 CPU 的首选方式是通过 Millicores，因为 API 会将整数转换为 Millicores。

对于内存分配，您可以使用普通的内存单位，如千字节或基字节；其他内存单位也是如此，如 E、P、T、G 和 M。

回到资源配额，我们可以看到单个容器资源管理将如何与命名空间中的资源配额一起发挥作用。这是因为资源配额将告诉我们在容器中每个命名空间中可以设置多少限制和请求。

我们没有修改的第二个字段是`env`字段。通过`env`，我们为容器配置环境变量。通过变量声明，我们可以将设置、参数、密码和更多配置传递给我们的容器。在 pod 中声明变量的最简单方式如下：

```
...
env:
-  name: VAR
  value: “Hello World”
```

现在容器将可以在其 shell 中访问`VAR`变量内容，称为`$VAR`。正如我们之前提到的，这是声明变量并为其提供值的最简单方式。然而，这并不是最有效的方式——当您以这种方式声明值时，该值将仅存在于 pod 声明中。

如果我们需要编辑值或将该值传递给多个 pod，这将变得很麻烦，因为您需要在每个需要它的 pod 上键入相同的值。这就是我们将介绍另外两个 Kubernetes API 对象：`Secrets`和`ConfigMaps`的地方。

通过`ConfigMaps`和`Secrets`，我们可以以持久且更模块化的形式存储变量的值。实质上，`ConfigMaps`和`Secrets`是相同的，但是 secrets 中包含的值是以`base64`编码的。Secrets 用于存储诸如密码或私钥等敏感信息，基本上是任何类型的机密数据。您不需要隐藏的所有其他数据都可以通过`ConfigMap`传递。

创建这两种类型的对象的方式与 Kubernetes 中的任何其他对象相同——通过`YAML`。您可以按以下方式创建`ConfigMap`对象：

```
apiVersion: v1
 kind: ConfigMap
 metadata:
  name: my-config
 data:
 super.data: much-data
 very.data: wow
```

在这个定义上唯一的区别，与本章中的所有其他定义相比，就是我们缺少了`specification`字段。相反，我们有`data`，在其中我们将放置包含我们想要存储的数据的键值对。

对于`Secrets`，这个过程有点不同。这是因为我们需要存储的密钥的值必须进行编码。为了将值存储在秘密的键中，我们将值传递给`base64`，如下所示：

```
[dsala@RedFedora]$ echo -n “our secret” | base64
WW91IEhhdmUgRGVjb2RlZCBNeSBTZWNyZXQhIENvbmdyYXR6IQ==
```

当我们有字符串的`base64`哈希时，我们就可以创建我们的秘密了。

以下代码块显示了一个使用`base64`配置了秘密值的`YAML`文件：

```
apiVersion: v1
 kind: Secret
 metadata:
  name: kube-secret
 type: Opaque
 data:
  password: WW91IEhhdmUgRGVjb2RlZCBNeSBTZWNyZXQhIENvbmdyYXR6IQ==
```

使用我们的`ConfigMaps`和`Secrets`对象在 pod 中，我们在`env`数组中使用`valueFrom`字段：

```
apiVersion: v1
 kind: Pod
 metadata:
  name: secret-pod
 spec:
  containers:
  - name: secret-container
    image: busybox
    env:
      - name: SECRET_VAR
        valueFrom:
          secretKeyRef:
            name: kube-secret
            key: password
```

在这里，`secretKeyRef`下的名称对应于`Secret` API 对象的名称，而`key`是`Secret`中`data`字段中的`key`。

对于`ConfigMaps`，它看起来几乎一样；但是，在`valueFrom`字段中，我们将使用`configMapKeyRef`而不是`secretKeyRef`。

`ConfigMap`声明如下：

```
    …
    env:
            -   name: CONFMAP_VAR
                valueFrom:
                   configMapKeyRef:
                      name: my-config
                      key: very.data
```

现在您已经了解了定制 pod 的基础知识，您可以查看一个真实的示例，网址为[`kubernetes.io/docs/tutorials/configuration/configure-redis-using-configmap/`](https://kubernetes.io/docs/tutorials/configuration/configure-redis-using-configmap/)。

# 摘要

在本章中，我们学习了如何确定 Kubernetes 集群的计算和网络要求。我们还涉及了随之而来的软件要求，比如`etcd`，以及为什么奇数编号的集群更受青睐（由于人口普查算法），因为集群需要获得超过 50%的选票才能达成共识。

`etcd`集群可以在 kube-apiserver 上运行，也可以有一个专门用于`etcd`的独立集群。在资源方面，2 个 CPU 和 8GB 的 RAM 应该足够了。在决定`etcd`的存储系统时，选择延迟较低、IOPS 较高的存储，如 SSD。然后我们开始调整 kube-apiserver 的大小，它可以与`etcd`一起运行。鉴于这两个组件可以共存，每个节点的资源应该在 8 到 16GB 的 RAM 和 2 到 4 个 CPU 之间。

为了正确调整工作节点的大小，我们必须记住这是实际应用工作负载将要运行的地方。这些节点应根据应用程序要求进行调整，并且在可能会运行超过计划数量的 pod 的时期，例如在滚动更新期间，应考虑额外的资源。继续讨论集群的要求，我们提到负载均衡器如何通过在集群中平衡请求来帮助主节点的通信。

Kubernetes 的存储需求可能会非常庞大，因为许多因素可能会影响整体设置，倾向于选择有利于读取而不是写入的存储系统更可取。此外，Kubernetes 的一些最常见的存储提供者如下：

+   Ceph

+   GlusterFS（在第二章中涵盖，*定义 GlusterFS 存储*到第五章，*分析 Gluster 系统的性能*）

+   OpenStack Cinder

+   NFS

然后我们转向网络方面，了解了 Kubernetes 如何提供诸如基于 DNS 的服务发现之类的服务，负责在集群中创建所有 DNS 记录并为服务发现提供 DNS 请求。Kubernetes 中的对象可以定制以适应每个工作负载的不同需求，而诸如命名空间之类的东西被用作将您的集群分成多个虚拟集群的一种方式。资源限制可以通过资源配额来实现。

最后，可以定制 pod 以允许分配绝对最大的资源，并避免单个 pod 消耗所有工作节点的资源。我们详细讨论了各种存储考虑和要求，包括如何定制 kube 对象和 pod。

在下一章中，我们将介绍如何部署 Kubernetes 集群并学习如何配置它。

# 问题

1.  为什么奇数编号的`etcd`集群更受青睐？

1.  `etcd`可以与 kube-apiserver 一起运行吗？

1.  为什么建议`etcd`的延迟较低？

1.  什么是工作节点？

1.  在调整工作节点大小时应考虑什么？

1.  Kubernetes 的一些存储提供者是什么？

1.  为什么需要负载均衡器？

1.  命名空间如何使用？

# 进一步阅读

+   *掌握 Kubernetes* 作者 Gigi Sayfan：[`www.packtpub.com/virtualization-and-cloud/mastering-kubernetes`](https://www.packtpub.com/virtualization-and-cloud/mastering-kubernetes)

+   *面向开发人员的 Kubernetes* 作者 Joseph Heck：[`www.packtpub.com/virtualization-and-cloud/kubernetes-developers`](https://www.packtpub.com/virtualization-and-cloud/kubernetes-developers)

+   *使用 Kubernetes 进行微服务实践* 作者 Gigi Sayfan：[`www.packtpub.com/virtualization-and-cloud/hands-microservices-kubernetes`](https://www.packtpub.com/virtualization-and-cloud/hands-microservices-kubernetes)

+   *开始使用 Kubernetes-第三版* 作者 Jonathan Baier，Jesse White：[`www.packtpub.com/virtualization-and-cloud/getting-started-kubernetes-third-edition`](https://www.packtpub.com/virtualization-and-cloud/getting-started-kubernetes-third-edition)

+   *掌握 Docker-第二版* 作者 Russ McKendrick，Scott Gallagher：[`www.packtpub.com/virtualization-and-cloud/mastering-docker-second-edition`](https://www.packtpub.com/virtualization-and-cloud/mastering-docker-second-edition)

+   《Docker Bootcamp》由 Russ McKendrick 等人编写：[`www.packtpub.com/virtualization-and-cloud/docker-bootcamp`](https://www.packtpub.com/virtualization-and-cloud/docker-bootcamp)


# 第九章：部署和配置 Kubernetes

在了解了 Kubernetes 内部组件及其相互作用方式之后，现在是时候学习如何设置它们了。手动安装 Kubernetes 集群可能是一个非常痛苦和微妙的过程，但通过完成所需的步骤，我们可以更好地学习和理解其内部组件。在执行手动安装后，我们还可以探索其他可用于自动化此过程的替代方案和工具。以下是本章将学习的内容的摘要：

+   创建我们的计算环境

+   引导控制平面

+   引导工作节点

+   配置集群网络和 DNS 设置

+   托管 Kubernetes 服务的示例

通过每一步，我们将更接近完成 Kubernetes 的完整安装，并准备在开发环境中进行测试。

# 基础设施部署

为了部署将运行我们的 Kubernetes 集群的基础设施，我们将使用 Microsoft Azure。您可以通过创建免费试用或使用任何其他公共云提供商，或者您自己的本地 IT 基础设施来跟随。具体步骤将取决于您的选择。

# 安装 Azure CLI

在使用 Linux 时，在 Azure 中部署资源有两种方式：您可以从门户或通过 Azure CLI 进行。我们将两者都使用，但用于不同的场景。

让我们开始在我们的 Linux 工作站或 Windows 子系统上安装 Azure CLI。

请注意，所有命令都假定由具有 root 权限的帐户或 root 帐户本身发出（但这并不推荐）。

对于基于 RHEL/Centos 的发行版，您需要执行以下步骤：

1.  下载并`import`存储库密钥，如下命令所示：

```
rpm --import https://packages.microsoft.com/keys/microsoft.asc
```

2. 创建存储库配置文件，如下命令所示：

```
cat << EOF > /etc/yum.repos.d/azure-cli.repo
[azure-cli]
name=Azure CLI
baseurl=https://packages.microsoft.com/yumrepos/azure-cli
enabled=1
gpgcheck=1
gpgkey=https://packages.microsoft.com/keys/microsoft.asc
EOF
```

3. 使用以下命令安装`azure-cli`：

```
yum install azure-cli
```

4. 使用以下命令登录到您的 Azure 订阅：

```
az login
```

如果您不在桌面环境中，您可以使用：az login --use-device-code，因为常规的“az login”需要通过 Web 浏览器执行登录。

安装 Azure CLI 后，我们仍然需要设置一些默认值，这样我们就不必一遍又一遍地输入相同的标志选项。

# 配置 Azure CLI

Azure 上的每个资源都位于资源组和地理位置中。因为我们所有的资源都将位于同一个资源组和位置中，让我们将它们配置为默认值。要做到这一点，请运行以下命令：

```
az configure --defaults location=eastus group=Kube_Deploy
```

对于我们的示例，我们将使用“东部”作为位置，因为这是离我们最近的位置。组名将取决于您将如何命名您的资源组-在我们的情况下，是`Kube_Deploy`。

配置了默认值后，让我们继续实际创建包含我们资源的资源组，使用以下命令：

```
az group create -n “Kube_Deploy”
```

# 高级设计概述

创建了我们的资源组并选择了我们的位置后，让我们通过以下代码高层次地查看我们将要创建的设计：

```
<design picture>
```

我们现在需要注意的重要事项是 VM 的数量、网络架构和防火墙规则，因为这些是我们将直接在我们的第一步中配置的元素。

在我们开始配置资源之前，让我们先看一下我们的网络需求。

我们有以下要求：

+   以下三组不同的、不重叠的子网：

+   VM 子网

+   Pod 子网

+   服务子网

+   以下资源的静态分配的 IP 地址：

+   主节点

+   工作节点

+   管理 VM

+   负载均衡器的公共 IP

+   DNS 服务器

对于我们的 VM 子网，我们将使用以下地址空间：

```
192.168.0.0/24
```

服务 CIDR 将如下：

```
10.20.0.0/24
```

最后，我们的 POD CIDR 将会更大一些，以便它可以分配更多的 POD，如下面的代码所示：

```
10.30.0.0/16
```

现在让我们开始配置我们需要使这种架构成为可能的网络资源。

# 配置网络资源

首先，我们将创建包含 VM 子网的虚拟网络。要做到这一点，运行以下命令：

```
az network vnet create -n kube-node-vnet \
 --address-prefix 192.168.0.0/16 \
 --subnet-name node-subnet \
 --subnet-prefix 192.168.0.0/24
```

这个命令中的两个关键点是`address-prefix`标志和`subnet-prefix`标志。

使用`address-prefix`标志，我们将指定定义 VNET 上可以放置哪些子网的地址空间。例如，我们的 VNET 前缀是`192.16.0.0/16`。这意味着我们不能在这个 CIDR 之外放置任何地址；例如，`10.0.0.0/24`是行不通的。

子网前缀将是分配给连接到我们子网的 VM 的地址空间。现在我们已经创建了我们的 VNET 和子网，我们需要一个静态的公共 IP 地址。在 Azure 和任何公共云提供商中，公共 IP 是与 VM 分开的资源。

通过运行以下命令来创建我们的公共 IP：

```
az network public-ip create -n kube-api-pub-ip \
 --allocation-method Static \
 --sku Standard
```

创建后，可以通过运行以下查询来记录 IP：

```
az network public-ip show -n kube-api-pub-ip --query "ipAddress"
```

有了我们的 VNET、子网和公共 IP 分配完毕，我们只需要最后一个资源，一个防火墙，为我们的 VMS 提供安全保障。在 Azure 中，防火墙称为**网络安全组**（**NSG**）。创建 NSG 的过程非常简单，如下命令所示：

```
az network nsg create -n kube-nsg
```

创建 NSG 后，我们使用以下命令将 NSG 分配给我们的子网：

```
az network vnet subnet update -n node-subnet \
 --vnet-name kube-node-vnet \
 --network-security-group kube-nsg
```

# 配置计算资源

网络设置完成后，我们准备开始创建一些 VM。但在创建任何 VM 之前，我们需要创建用于访问我们的 VM 的 SSH 密钥。

我们将创建的第一对密钥是用于我们的管理 VM。这个 VM 将是唯一一个可以从外部世界访问 SSH 的 VM。出于安全原因，我们不希望暴露任何集群节点的`22`端口。每当我们想要访问我们的任何节点时，我们都将从这个 VM 中进行访问。

要创建 SSH 密钥，请在您的 Linux 工作站上运行`ssh-keygen`：

```
ssh-keygen
```

现在让我们使用以下命令创建管理 VM：

```
az vm create -n management-vm \
 --admin-username <USERNAME> \
 --size Standard_B1s \
 --image CentOS \
 --vnet-name kube-node-vnet \
 --subnet node-subnet \
 --private-ip-address 192.168.0.99 \
 --nsg kube-nsg \
 --ssh-key-value ~/.ssh/id_rsa.pub
```

记得用所需的用户名替换`<USERNAME>`字段。

下一步是我们需要配置第一个 NSG 规则的地方。这个规则将允许来自我们自己网络的流量进入我们的管理 VM 的`22`端口，这样我们就可以通过 SSH 连接到它。让我们使用以下命令设置这个规则：

```
az network nsg rule create --nsg-name kube-nsg \
 -n mgmt_ssh_allow \
 --direction Inbound \
 --priority 100 \
 --access Allow \
 --description "Allow SSH From Home" \
 --destination-address-prefixes '192.168.0.99' \
 --destination-port-ranges 22 \
 --protocol Tcp \
 --source-address-prefixes '<YOUR IP>' \
 --source-port-ranges '*' \
 --direction Inbound
```

`source-address-prefixes`是您的 ISP 提供的公共 IP 地址，因为这些 IP 可能是动态的，如果发生变化，您可以在 Azure 门户中的网络安全组规则中编辑 IP。

现在让我们连接到我们的 VM，创建 SSH 密钥，以便我们可以连接到我们的集群 VM。要检索我们管理 VM 的公共 IP 地址，运行以下查询：

```
az vm show -d -n management-vm --query publicIps
```

现在让我们使用之前创建的私钥 SSH 进入我们的 VM，如下所示：

```
ssh <username>@<public ip> -i <path to private key>
```

只有在您使用与创建密钥对的用户不同的用户登录时，才需要指定私钥。

现在我们在管理 VM 中，再次运行`ssh-keygen`，最后退出 VM。

为了在 Azure 数据中心发生灾难时提供高可用性，我们的主节点将位于可用性集上。让我们创建可用性集。

如果您不记得可用性集是什么，您可以回到我们的 Gluster 章节，重新了解它的功能。

要创建可用性集，请运行以下命令：

```
az vm availability-set create -n control-plane \
 --platform-fault-domain-count 3 \
 --platform-update-domain-count 3
```

现在我们可以继续创建我们的第一个控制平面节点。让我们首先将我们管理 VM 的公共 SSH 密钥保存到一个变量中，以便将密钥传递给主节点，如下命令所示：

```
MGMT_KEY=$(ssh <username>@<public ip> cat ~/.ssh/id_rsa.pub)
```

要创建三个控制器节点，请运行以下`for`循环：

```

for i in 1 2 3; do
az vm create -n kube-controller-${i} \
 --admin-username <USERNAME> \
 --availability-set control-plane \
 --size Standard_B2s \
 --image CentOS \
 --vnet-name kube-node-vnet \
 --subnet node-subnet \
 --private-ip-address 192.168.0.1${i} \
 --public-ip-address "" \
 --nsg kube-nsg \
 --ssh-key-value ${MGMT_KEY};
done

```

我们在这些 VM 上使用的大小很小，因为这只是一个测试环境，我们实际上不需要很多计算资源。在真实环境中，我们会根据我们在第八章中探讨的考虑因素来确定 VM 的大小，*设计一个 Kubernetes 集群*。

最后但并非最不重要的，我们使用以下命令创建我们的工作节点：

```

for i in 1 2; do
az vm create -n kube-node-${i} \
 --admin-username <USERNAME>\
 --size Standard_B2s \
 --image CentOS \
 --vnet-name kube-node-vnet \
 --subnet node-subnet \
 --private-ip-address 192.168.0.2${i} \
 --public-ip-address "" \
 --nsg kube-nsg \
 --ssh-key-value ${MGMT_KEY}
done

```

# 准备管理 VM

创建了控制器和工作节点后，我们现在可以登录到我们的管理 VM 并开始安装和配置我们将需要引导我们的 Kubernetes 集群的工具。

从现在开始，我们大部分时间将在管理 VM 上工作。让我们 SSH 到 VM 并开始安装我们的工具集。

首先，我们需要下载工具来创建我们集群服务之间通信所需的证书。

首先使用以下命令安装依赖项：

```
johndoe@management-vm$ sudo yum install git gcc 

johndoe@management-vm$ sudo wget -O golang.tgz  https://dl.google.com/go/go1.11.1.linux-amd64.tar.gz 

johndoe@management-vm$ sudo tar -C /usr/local -xzvf golang.tgz
```

安装了**Go lang**后，您需要更新您的`PATH`变量并创建一个名为`GOPATH`的新变量。您的 TLS 证书生成工具 CFFSL 将安装在此路径下。为此，您可以执行以下操作：

```
johndoe@management-vm$ sudo cat << EOF > /etc/profile.d/paths.sh
export PATH=$PATH:/usr/local/go/bin:/usr/local/bin
export GOPATH=/usr/local/
EOF
```

然后运行以下命令在当前 shell 中加载变量：

```
johndoe@management-vm$ sudo source /etc/profile.d/paths.sh
```

变量设置好后，现在我们准备好使用以下命令获取我们的`cffsl`工具包：

```
johndoe@management-vm$ go get -u github.com/cloudflare/cfssl/cmd/cfssl

johndoe@management-vm$ go get -u github.com/cloudflare/cfssl/cmd/cfssljson
```

这两个二进制文件将保存在我们的`GOPATH`变量下。

# 生成证书

安装了 CFSSL 二进制文件并加载到我们的`PATH`中后，我们可以开始生成我们的证书文件。在此安装的这一部分中，我们将生成大量文件，因此最好创建一个目录结构来适当存储它们。

# 证书颁发机构

我们需要生成的第一个文件是用于签署其余组件证书的证书颁发机构文件。

我们将把所有证书存储在`~/certs/`目录下，但首先我们需要创建该目录。让我们使用以下命令设置这个目录：

```
johndoe@management-vm$ mkdir ~/certs
```

现在我们有了目录，让我们从以下命令开始生成 CA 配置文件，其中将包含由我们的 CA 签发的证书的到期日期以及 CA 将用于什么目的的信息：

```
johndoe@management-vm$ cd ~/certs

johndoe@management-vm$ cat << EOF > ca-config.json
{
 "signing": {
 "default": {
 "expiry": "8760h"
 },
 "profiles": {
 "kubernetes": {
 "usages": [
 "signing",
 "key encipherment",
 "server auth",
 "client auth"
 ],
 "expiry": "8760h"
 }
 }
 }
}
EOF
```

有了我们的 CA 配置，现在我们可以开始签发证书签名请求。

我们要生成的第一个 CSR 是用于我们的 CA 的。让我们使用以下命令设置这个：

```
johndoe@management-vm$ cat << EOF > ca-csr.json 
{
 "CN": "Kubernetes",
 "key": {
 "algo": "rsa",
 "size": 2048
 },
 "names": [
 {
 "C": "US",
 "L": "New York",
 "O": "Kubernetes",
 "OU": "CA",
 "ST": "NY"
 }
 ]
}
EOF
```

现在我们有了两个`JSON`文件，我们实际上可以使用`cffsl`并使用以下命令生成我们的证书：

```
johndoe@management-vm$ cfssl gencert -initca ca-csr.json | cfssljson -bare ca
```

如下命令所示，将生成三个文件，`ca.csr`，`ca.pem`和`ca-key.pem`。第一个`ca.csr`是证书签名请求。另外两个分别是我们的公共证书和私钥：

```
johndoe@management-vm$ ls
ca-config.json  ca.csr ca-csr.json  ca-key.pem ca.pem
```

从现在开始，我们生成的任何证书都将是这种情况。

# 客户端证书

现在我们的 CA 已配置并生成了其证书文件，我们可以开始为我们的管理员用户和每个工作节点上的 kubelet 签发证书。

我们要创建的过程和文件与 CA 的非常相似，但在生成它们所使用的命令中有轻微的差异。

使用以下命令创建我们的`admin certs`目录：

```
johndoe@management-vm$ mkdir ~/certs/admin/

johndoe@management-vm$ cd ~/certs/admin/
```

首先，创建管理员用户证书。此证书是供我们的管理员通过`kubectl`管理我们的集群使用的。

同样，我们将使用以下命令生成`csr`的`json`：

```
johndoe@management-vm$ cat << EOF > admin-csr.json 
{
 "CN": "admin",
 "key": {
 "algo": "rsa",
 "size": 2048
 },
 "names": [
 {
 "C": "US",
 "L": "New York",
 "O": "system:masters",
 "OU": "Kubernetes",
 "ST": "NY"
 }
 ]
}
EOF
```

有了我们的 JSON 准备好了，现在让我们使用以下命令签名并创建管理员证书：

```
johndoe@management-vm$ cfssl gencert \
 -ca=../ca.pem \
 -ca-key=../ca-key.pem \
 -config=../ca-config.json \
 -profile=kubernetes \
 admin-csr.json | cfssljson -bare admin
```

与管理员和 CA 证书相比，创建`kubelet`证书的过程有些不同。`kubelet`证书要求我们在证书中填写主机名字段，因为这是它的标识方式。

使用以下命令创建目录：

```
johndoe@management-vm$ mkdir ~/certs/kubelet/

johndoe@management-vm$ cd ~/certs/kubelet/
```

然后使用以下命令创建`json` `csr`，其中没有太多变化：

```
johndoe@management-vm$ cat << EOF > kube-node-1-csr.json
{
 "CN": "system:node:kube-node-1",
 "key": {
 "algo": "rsa",
 "size": 2048
 },
 "names": [
 {
 "C": "US",
 "L": "New York",
 "O": "system:nodes",
 "OU": "Kubernetes",
 "ST": "NY"
 }
 ]
}
EOF
```

然而，当生成`certs`时，过程有些不同，如下命令所示：

```
johndoe@management-vm$ cfssl gencert \
 -ca=../ca.pem \
 -ca-key=../ca-key.pem \
 -config=../ca-config.json \
 -hostname=192.168.0.21,kube-node-1 \
 -profile=kubernetes \
 kube-node-1-csr.json | cfssljson -bare kube-node-1
```

如您所见，主机名字段将包含节点将具有的任何 IP 或 FQDN。现在为每个工作节点生成证书，填写与生成证书的节点对应的信息。

# 控制平面证书

让我们开始为我们的 kube 主要组件创建证书。

与之前的步骤一样，创建一个包含主节点组件证书的目录，并按以下方式为每个组件生成证书文件：

```
johndoe@management-vm$ mkdir ~/certs/control-plane/

johndoe@management-vm$ cd ~/certs/control-plane/
```

对于`kube-controller-manager`，使用以下命令：

```
johndoe@management-vm$ cat << EOF > kube-controller-manager-csr.json
{
 "CN": "system:kube-controller-manager",
 "key": {
 "algo": "rsa",
 "size": 2048
 },
 "names": [
 {
 "C": "US",
 "L": "New York",
 "O": "system:kube-controller-manager",
 "OU": "Kubernetes",
 "ST": "NY"
 }
 ]
}
EOF

johndoe@management-vm$ cfssl gencert \
 -ca=../ca.pem \
 -ca-key=../ca-key.pem \
 -config=../ca-config.json \
 -profile=kubernetes \
 kube-controller-manager-csr.json | cfssljson -bare kube-controller-manager
```

对于`kube-proxy`，使用以下命令：

```
johndoe@management-vm$ cat << EOF > kube-proxy-csr.json
{
 "CN": "system:kube-proxy",
 "key": {
 "algo": "rsa",
 "size": 2048
 },
 "names": [
 {
 "C": "US",
 "L": "New York",
 "O": "system:node-proxier",
 "OU": "Kubernetes",
 "ST": "NY"
 }
 ]
}
EOF

johndoe@management-vm$ cfssl gencert \
 -ca=../ca.pem \
 -ca-key=../ca-key.pem \
 -config=../ca-config.json \
 -profile=kubernetes \
 kube-proxy-csr.json | cfssljson -bare kube-proxy
```

对于`kube-scheduler`，使用以下命令：

```
johndoe@management-vm$ cat << EOF > kube-scheduler-csr.json
{
 "CN": "system:kube-scheduler",
 "key": {
 "algo": "rsa",
 "size": 2048
 },
 "names": [
 {
 "C": "US",
 "L": "New York",
 "O": "system:kube-scheduler",
 "OU": "Kubernetes",
 "ST": "NY"
 }
 ]
}
EOF

johndoe@management-vm$ cfssl gencert \
 -ca=../ca.pem \
 -ca-key=../ca-key.pem \
 -config=../ca-config.json \
 -profile=kubernetes \
 kube-scheduler-csr.json | cfssljson -bare kube-scheduler
```

现在我们需要创建 API 服务器。您会注意到它与我们在`kubelets`中使用的过程类似，因为这个证书需要主机名参数。但是对于`kube-api`证书，我们不仅会提供单个节点的主机名和 IP 地址，还会提供 API 服务器将使用的所有可能的主机名和 IP 地址：负载均衡器的公共 IP，每个主节点的 IP，以及一个特殊的 FQDN，`kubernetes.default`。所有这些将包含在一个单独的证书中。

首先使用以下命令创建一个单独的目录：

```
johndoe@management-vm$ mkdir ~/certs/api/

johndoe@management-vm$ cd ~/certs/api/
```

现在，让我们使用以下命令为主机名创建一个变量：

```
johndoe@management-vm$API_HOSTNAME=10.20.0.1,192.168.0.11,kube-controller-1,192.168.0.12,kube-controller-2,<PUBLIC_IP>,127.0.0.1,localhost,kubernetes.default
```

请注意，您应该用您的公共 IP 地址替换`<PUBLIC_IP>`。

现在，让我们使用以下命令创建证书：

```
johndoe@management-vm$ cat << EOF > kubernetes-csr.json 
{
 "CN": "kubernetes",
 "key": {
 "algo": "rsa",
 "size": 2048
 },
 "names": [
 {
 "C": "US",
 "L": "New York",
 "O": "Kubernetes",
 "OU": "Kubernetes",
 "ST": "NY"
 }
 ]
}
EOF

johndoe@management-vm$ cfssl gencert \
 -ca=../ca.pem \
 -ca-key=../ca-key.pem \
 -config=../ca-config.json \
 -hostname=${API_HOSTNAME} \
 -profile=kubernetes \
 kubernetes-csr.json | cfssljson -bare kubernetes
```

此时，只缺少一个证书——服务账户证书。这个证书不是为任何普通用户或 Kubernetes 组件特定的。服务账户证书由 API 服务器用于签署用于服务账户的令牌。

我们将把这些密钥对存储在与 API 证书相同的目录中，所以我们只需创建`json`并运行`cfssl` `gencert`命令，如下命令所示：

```
johndoe@management-vm$ cat << EOF > service-account-csr.json 
{
 "CN": "service-accounts",
 "key": {
 "algo": "rsa",
 "size": 2048
 },
 "names": [
 {
 "C": "US",
 "L": "New York",
 "O": "Kubernetes",
 "OU": "Kubernetes",
 "ST": "NY"
 }
 ]
}
EOF

johndoe@management-vm$ cfssl gencert \
 -ca=../ca.pem \
 -ca-key=../ca-key.pem \
 -config=../ca-config.json \
 -profile=kubernetes \
 service-account-csr.json | cfssljson -bare service-account
```

# 发送我们的证书回家

所有证书生成完毕后，是时候将它们移动到相应的节点上了。Microsoft Azure 可以通过 VM 名称内部解析，所以我们可以轻松地移动证书。

使用以下命令将证书移动到`kubelets`：

```
johndoe@management-vm$ cd ~/certs/kubelets

johndoe@management-vm$ scp ../ca.pem \
kube-node-1.pem \
kube-node-1-key.pem \
johndoe@kube-node-1:~/
```

对于其余的节点重复以上步骤。

使用以下命令将证书移动到控制平面：

```
johndoe@management-vm$ cd ~/certs/api

johndoe@management-vm$ scp ../ca.pem \
../ca-key.pem \
kubernetes.pem \
kubernetes-key.pem \
service-account.pem \
service-account-key.pem \
johndoe@kube-controller-1:~/
```

对最后的控制器重复以上步骤。

# Kubeconfigs

要能够与 Kubernetes 通信，您需要知道 API 的位置。您还需要告诉 API 您是谁以及您的凭据是什么。所有这些信息都包含在`kubeconfigs`中。这些配置文件包含了您到达和对集群进行身份验证所需的所有信息。用户不仅将使用`kubeconfig`文件来访问集群，还将使用它来访问其他服务。这就是为什么我们将为每个组件和用户生成多个`kubeconfig`文件。

# 安装 kubectl

要能够创建`kubeconfig`文件，我们需要`kubectl`。您将首先在管理 VM 中安装`kubectl`以生成配置文件，但稍后我们还将使用它来管理我们的集群。

首先，添加我们将获取`kubectl`的存储库，如下命令所示：

```
johndoe@management-vm$ sudo cat << EOF > /etc/yum.repos.d/kubernetes.repo
[kubernetes]
name=Kubernetes
baseurl=https://packages.cloud.google.com/yum/repos/kubernetes-el7-x86_64
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=https://packages.cloud.google.com/yum/doc/yum-key.gpg https://packages.cloud.google.com/yum/doc/rpm-package-key.gpg
EOF
```

最后，使用`yum`进行安装，如下命令所示：

```
johndoe@management-vm$sudo yum install kubectl
```

# 控制平面 kubeconfigs

我们将要生成的第一个 kubeconfigs 是我们的控制平面组件。

为了保持秩序，我们将继续将文件组织到目录中。所有我们的`kubeconfigs`将放在同一个目录中，如下命令所示：

```
johndoe@management-vm$ mkdir ~/kubeconfigs

johndoe@management-vm$ cd ~/kubeconfigs
```

有了我们创建的目录，让我们开始生成`kubeconfigs`！

# Kube-controller-manager

`kube-controller-manager` `kubeconfig`：

```
johndoe@management-vm$ kubectl config set-cluster kubernetes \
 --certificate-authority=../certs/ca.pem \
 --embed-certs=true \
 --server=https://127.0.0.1:6443 \
 --kubeconfig=kube-controller-manager.kubeconfig

johndoe@management-vm$ kubectl config set-credentials \
system:kube-controller-manager \
 --client-certificate=../certs/control-plane/kube-controller-manager.pem \
 --client-key=../certs/control-plane/kube-controller-manager-key.pem \
 --embed-certs=true \
 --kubeconfig=kube-controller-manager.kubeconfig

johndoe@management-vm$ kubectl config set-context default \
 --cluster=kubernetes \
 --user=system:kube-controller-manager \
 --kubeconfig=kube-controller-manager.kubeconfig

johndoe@management-vm$ kubectl config use-context default --kubeconfig=kube-controller-manager.kubeconfig
```

# Kube-scheduler

`Kube-scheduler` `kubeconfig`：

```
johndoe@management-vm$ kubectl config set-cluster kubernetes \
 --certificate-authority=../certs/ca.pem \
 --embed-certs=true \
 --server=https://127.0.0.1:6443 \
 --kubeconfig=kube-scheduler.kubeconfig

johndoe@management-vm$ kubectl config set-credentials system:kube-scheduler \
 --client-certificate=../certs/control-plane/kube-scheduler.pem \
 --client-key=../certs/control-plane/kube-scheduler-key.pem \
 --embed-certs=true \
 --kubeconfig=kube-scheduler.kubeconfig

johndoe@management-vm$ kubectl config set-context default \
 --cluster=kubernetes \
 --user=system:kube-scheduler \
 --kubeconfig=kube-scheduler.kubeconfig

johndoe@management-vm$ kubectl config use-context default --kubeconfig=kube-scheduler.kubeconfig
```

# Kubelet 配置

对于我们的`kubelets`，我们将需要每个节点一个`kubeconfig`。为了简化操作，我们将使用 for 循环为每个节点创建一个配置，如下命令所示。请注意，您需要用您自己的公共 IP 地址替换`<KUBE_API_PUBLIC_IP>`：

```
johndoe@management-vm$ for i in 1 2; do
kubectl config set-cluster kubernetes \
--certificate-authority=../certs/ca.pem \
--embed-certs=true \
--server=https://<KUBE_API_PUBLIC_IP>:6443 \
--kubeconfig=kube-node-${i}.kubeconfig

kubectl config set-credentials system:node:kube-node-${i} \
--client-certificate=../certs/kubelets/kube-node-${i}.pem \
--client-key=../certs/kubelets/kube-node-${i}-key.pem \
--embed-certs=true \
--kubeconfig=kube-node-${i}.kubeconfig

kubectl config set-context default \
--cluster=kubernetes \
--user=system:node:kube-node-${i} \
--kubeconfig=kube-node-${i}.kubeconfig

kubectl config use-context default --kubeconfig=kube-node-${i}.kubeconfig
done
```

最后，我们的工作节点将需要的最后一个`kubeconfig`是`kube-proxy kubeconfig`。我们只会生成一个，因为它不包含任何特定的节点配置，我们可以将相同的配置复制到所有节点。

# Kube-proxy

`kube-proxy` `kubeconfig`：

```
 johndoe@management-vm$ kubectl config set-cluster kubernetes \
 --certificate-authority=../certs/ca.pem \
 --embed-certs=true \
 --server=https://<PUBLIC_IP>:6443 \
 --kubeconfig=kube-proxy.kubeconfig

johndoe@management-vm$ kubectl config set-credentials system:kube-proxy \
 --client-certificate=../certs/controllers/kube-proxy.pem \
 --client-key=../certs/controllers/kube-proxy-key.pem \
 --embed-certs=true \
 --kubeconfig=kube-proxy.kubeconfig

johndoe@management-vm$ kubectl config set-context default \
 --cluster=kubernetes \
 --user=system:kube-proxy \
 --kubeconfig=kube-proxy.kubeconfig

johndoe@management-vm$ kubectl config use-context default \ --kubeconfig=kube-proxy.kubeconfig
```

现在我们有了控制平面 kubeconfigs 和工作节点，我们现在将使用以下命令为管理员用户创建`kubeconfig`。这个`kubeconfig`文件是我们将用来连接到集群并管理其 API 对象的文件：

```
johndoe@management-vm$ kubectl config set-cluster kubernetes \
 --certificate-authority=../certs/ca.pem \
 --embed-certs=true \
 --server=https://127.0.0.1:6443 \
 --kubeconfig=admin.kubeconfig

johndoe@management-vm$ kubectl config set-credentials admin \
 --client-certificate=../certs/admin/admin.pem \
 --client-key=../certs/admin/admin-key.pem \
 --embed-certs=true \
 --kubeconfig=admin.kubeconfig

johndoe@management-vm$ kubectl config set-context default \
 --cluster=kubernetes \
 --user=admin \
 --kubeconfig=admin.kubeconfig

johndoe@management-vm$ kubectl config use-context default \ --kubeconfig=admin.kubeconfig
```

# 移动配置文件

现在我们的 kubeconfigs 需要传输到它们各自的 VM。为此，我们将遵循与移动证书相同的过程。

首先，让我们使用以下命令移动进入工作节点的 kubeconfigs：

```
johndoe@management-vm$ scp kube-node-1.kubeconfig kube-proxy.kubeconfig johndoe@kube-node-1:~/
```

对每个节点重复。

在节点上放置了 kubeconfigs 后，我们现在可以使用以下命令移动`kube-api`服务器配置：

```
johndoe@management-vm$ scp admin.kubeconfig kube-controller-manager.kubeconfig \
kube-scheduler.kubeconfig johndoe@kube-controller-1:~/
```

对每个控制器重复。

# 安装控制平面

现在我们将安装控制平面所需的二进制文件。

# ETCD

在这个设计中，我们决定将`etcd`与我们的`kube-apiserver`一起运行。我们将开始下载二进制文件并为我们的数据库配置`systemd`单元。

# 安装 etcd

现在是时候在我们的控制器节点中开始安装`etcd`集群了。要安装`etcd`，我们将从管理 VM 中 SSH 到每个控制器并运行以下程序。

我们将通过以下命令下载和提取二进制文件：

```
johndoe@kube-controller-1$ wget -O etcd.tgz \ 
https://github.com/etcd-io/etcd/releases/download/v3.3.10/etcd-v3.3.10-linux-amd64.tar.gz

johndoe@kube-controller-1$ tar xzvf etcd.tgz

johndoe@kube-controller-1$ sudo mv etcd-v3.3.10-linux-amd64/etcd* /usr/local/bin/

johndoe@kube-controller-1$ sudo mkdir -p /etc/etcd /var/lib/etcd
```

在提取了二进制文件之后，我们需要使用以下命令将 kubernetes API 和 CA 证书复制到我们的`etcd`目录中：

```
johndoe@kube-controller-1$ cp /home/johndoe/ca.pem \
/home/johndoe/kubernetes-key.pem \
/home/johndoe/kubernetes.pem /etc/etcd
```

在创建`systemd`单元文件之前，让我们设置一些变量，以使事情变得更容易一些。

这两个变量将是唯一的，如以下命令所示：

```
johndoe@kube-controller-1$ ETCD_NAME=$(hostname)

johndoe@kube-controller-1$ I_IP=192.168.0.11
```

下一个和最后一个变量将在所有节点上相同；它将包含每个`ectd`集群成员的主机名和 IP，如以下命令所示：

```
I_CLUSTER=kube-controller-1=https://192.168.0.11:2380,kube-controller-2=https://192.168.0.12:2380,kube-controller-3=https://192.168.0.13:2380
```

现在我们有了变量，让我们创建`systemd`单元文件，如以下命令所示：

```
johndoe@kube-controller-1$sudo cat << EOF | sudo tee /etc/systemd/system/etcd.service
[Unit]
Description=etcd
Documentation=https://github.com/coreos

[Service]
ExecStart=/usr/local/bin/etcd \\
 --name ${ETCD_NAME} \\
 --cert-file=/etc/etcd/kubernetes.pem \\
 --key-file=/etc/etcd/kubernetes-key.pem \\
 --peer-cert-file=/etc/etcd/kubernetes.pem \\
 --peer-key-file=/etc/etcd/kubernetes-key.pem \\
 --trusted-ca-file=/etc/etcd/ca.pem \\
 --peer-trusted-ca-file=/etc/etcd/ca.pem \\
 --peer-client-cert-auth \\
 --client-cert-auth \\
 --initial-advertise-peer-urls https://${I_IP}:2380 \\
 --listen-peer-urls https://${I_IP}:2380 \\
 --listen-client-urls https://${I_IP}:2379,https://127.0.0.1:2379 \\
 --advertise-client-urls https://${I_IP}:2379 \\
 --initial-cluster-token etcd-cluster-0 \\
 --initial-cluster ${I_CLUSTER} \\
 --initial-cluster-state new \\
 --data-dir=/var/lib/etcd
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
```

现在我们重新加载、启用并启动守护进程，使用以下命令：

```
johndoe@kube-controller-1$ systemctl daemon-reload && \
systemctl enable etcd && \
systemctl start etcd && \
systemctl status etcd
```

一旦您为每个节点重复了这个过程，您可以通过运行以下命令来检查集群的状态：

```
johndoe@kube-controller-3$ ETCDCTL_API=3 etcdctl member list \
--endpoints=https://127.0.0.1:2379 \
--cacert=/etc/etcd/ca.pem \
--cert=/etc/etcd/kubernetes.pem \
--key=/etc/etcd/kubernetes-key.pem
```

# 加密 etcd 数据

API 服务器可以加密存储在`etcd`中的数据。为此，我们将在创建`kube-apiserver systemd`单元文件时使用一个名为`--experimental-encryption-provider-config`的标志。但在传递该标志之前，我们需要创建一个包含我们加密密钥的 YAML。

我们只会创建一个 YAML 定义并将其复制到每个控制器节点。您应该从管理 VM 执行此操作，以便可以轻松地将文件传输到所有控制器。让我们使用以下命令设置这一点：

```
johndoe@management-vm$ CRYPT_KEY=$(head -c 32 /dev/urandom | base64)
```

输入 YAML 定义如下：

```
johndoe@management-vm$ cat << EOF > crypt-config.yml
kind: EncryptionConfig
apiVersion: v1
resources:
 - resources:
 - secrets
 providers:
 - aescbc:
 keys:
 - name: key1
 secret: ${CRYPT_KEY}
 - identity: {}
EOF
```

最后，使用以下命令将密钥移动到每个节点：

```
johndoe@management-vm$ for i in 1 2 3; do
scp crypt-config.yml johndoe@kube-controller-${i}:~/
done
```

# 安装 Kubernetes 控制器二进制文件

现在`etcd`已经就位，我们可以开始安装`kube-apiserver`、`kube-controller-manager`和`kube-scheduler`。

# Kube-apiserver

让我们从第一个控制器节点 SSH 并使用以下命令下载所需的二进制文件：

```
johndoe@management-vm$ ssh johndoe@kube-controller-1

johndoe@kube-controller-1$ wget "https://storage.googleapis.com/kubernetes-release/release/v1.12.0/bin/linux/amd64/kube-apiserver" \
"https://storage.googleapis.com/kubernetes-release/release/v1.12.0/bin/linux/amd64/kubectl["](https://storage.googleapis.com/kubernetes-release/release/v1.12.0/bin/linux/amd64/kubectl)
```

现在使用以下命令将二进制文件移动到`/usr/local/bin/`：

```
johndoe@kube-controller-1$ sudo mkdir -p /etc/kubernetes/config

johndoe@kube-controller-1$ sudo chmod +x kube*

johndoe@kube-controller-1$ sudo mv kube-apiserver kubectl /usr/local/bin/
```

接下来，我们将使用以下命令创建和移动所有 API 服务器所需的目录和证书：

```
johndoe@kube-controller-1$ sudo mkdir -p /var/lib/kubernetes/

johndoe@kube-controller-1$ sudo cp /home/johndoe/ca.pem \
/home/johndoe/ca-key.pem \
/home/johndoe/kubernetes-key.pem \
/home/johndoe/kubernetes.pem \
/home/johndoe/service-account-key.pem \
/home/johndoe/service-account.pem \
/home/johndoe/crypt-config.yml \
/var/lib/kubernetes/
```

在创建`systemd`单元文件之前，让我们使用以下命令声明一些变量：

```
johndoe@kube-controller-1$ I_IP=192.168.0.11

johndoe@kube-controller-1$ CON1_IP=192.168.0.11

johndoe@kube-controller-1$ CON2_IP=192.168.0.12

johndoe@kube-controller-1$ CON2_IP=192.168.0.13
```

只有`I_IP`变量在每个节点上是唯一的，它将取决于您正在执行该过程的节点的 IP。其他三个变量在所有节点上都是相同的。

现在变量设置好了，我们可以开始创建单元文件，如以下命令所示：

```
johndoe@kube-controller-1$ sudo cat << EOF | sudo tee /etc/systemd/system/kube-apiserver.service
[Unit]
Description=Kubernetes API Server
Documentation=https://github.com/kubernetes/kubernetes

[Service]
ExecStart=/usr/local/bin/kube-apiserver \\
 --advertise-address=${I_IP} \\
 --allow-privileged=true \\
 --apiserver-count=3 \\
 --audit-log-maxage=30 \\
 --audit-log-maxbackup=3 \\
 --audit-log-maxsize=100 \\
 --audit-log-path=/var/log/audit.log \\
 --authorization-mode=Node,RBAC \\
 --bind-address=0.0.0.0 \\
 --client-ca-file=/var/lib/kubernetes/ca.pem \\
 --enable-admission-plugins=Initializers,NamespaceLifecycle,NodeRestriction,LimitRanger,ServiceAccount,DefaultStorageClass,ResourceQuota \\
 --enable-swagger-ui=true \\
 --etcd-cafile=/var/lib/kubernetes/ca.pem \\
 --etcd-certfile=/var/lib/kubernetes/kubernetes.pem \\
 --etcd-keyfile=/var/lib/kubernetes/kubernetes-key.pem \\
 --etcd-servers=https://$CON1_IP:2379,https://$CON2_IP:2379 \\
 --event-ttl=1h \\
 --experimental-encryption-provider-config=/var/lib/kubernetes/crypt-config.yml \\
 --kubelet-certificate-authority=/var/lib/kubernetes/ca.pem \\
 --kubelet-client-certificate=/var/lib/kubernetes/kubernetes.pem \\
 --kubelet-client-key=/var/lib/kubernetes/kubernetes-key.pem \\
 --kubelet-https=true \\
 --runtime-config=api/all \\
 --service-account-key-file=/var/lib/kubernetes/service-account.pem \\
 --service-cluster-ip-range=10.20.0.0/24 \\
 --service-node-port-range=30000-32767 \\
 --tls-cert-file=/var/lib/kubernetes/kubernetes.pem \\
 --tls-private-key-file=/var/lib/kubernetes/kubernetes-key.pem \\
 --v=2 \\
 --kubelet-preferred-address-types=InternalIP,InternalDNS,Hostname,ExternalIP,ExternalDNS
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
```

# Kube-controller-manager

要安装`kube-controller-manager`，步骤将非常相似，只是在这一点上，我们将开始使用 kubeconfigs。

首先，使用以下命令下载`kube-controller-manager`：

```
johndoe@kube-controller-1$ wget "https://storage.googleapis.com/kubernetes-release/release/v1.12.0/bin/linux/amd64/kube-controller-manager"

johndoe@kube-controller-1$sudo chmod +x kube-controller-manager

johndoe@kube-controller-1$sudo mv kube-controller-manager /usr/local/bin/
```

使用以下命令移动`kubeconfig`并创建`kube-controller-manager`的单元文件：

```
johndoe@kube-controller-1$ sudo cp \
/home/johndoe/kube-controller-manager.kubeconfig /var/lib/kubernetes/

johndoe@kube-controller-1$ cat << EOF | sudo tee \ /etc/systemd/system/kube-controller-manager.service
[Unit]
Description=Kubernetes Controller Manager
Documentation=https://github.com/kubernetes/kubernetes

[Service]
ExecStart=/usr/local/bin/kube-controller-manager \\
 --address=0.0.0.0 \\
 --cluster-cidr=10.30.0.0/16 \\
 --cluster-name=kubernetes \\
 --cluster-signing-cert-file=/var/lib/kubernetes/ca.pem \\
 --cluster-signing-key-file=/var/lib/kubernetes/ca-key.pem \\
 --kubeconfig=/var/lib/kubernetes/kube-controller-manager.kubeconfig \\
 --leader-elect=true \\
 --root-ca-file=/var/lib/kubernetes/ca.pem \\
 --service-account-private-key-file=/var/lib/kubernetes/service-account-key.pem \\
 --service-cluster-ip-range=10.20.0.0/24 \\
 --use-service-account-credentials=true \\
 --v=2
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
```

# Kube-scheduler

在控制平面中安装的最后一个组件是`kube-scheduler`。除了创建`systemd`单元文件外，我们还将创建一个包含调度程序基本配置的 YAML 文件。

首先，让我们下载二进制文件。使用以下命令下载`kube-scheduler`并将其移动到`/usr/local/bin/`：

```
johndoe@kube-controller-1$ wget \
"https://storage.googleapis.com/kubernetes-release/release/v1.12.0/bin/linux/amd64/kube-scheduler"

johndoe@kube-controller-1$ chmod +x kube-scheduler

johndoe@kube-controller-1$ sudo mv kube-scheduler /usr/local/bin/
```

使用以下命令将`kubeconfig`文件移动到`kubernetes`文件夹中：

```
johndoe@kube-controller-1$sudo cp /home/johndoe/kube-scheduler.kubeconfig /var/lib/kubernetes/
```

`kube-scheduler.yml`如下所示：

```
johndoe@kube-controller-1$sudo cat << EOF | sudo tee /etc/kubernetes/config/kube-scheduler.yml
apiVersion: componentconfig/v1alpha1
kind: KubeSchedulerConfiguration
clientConnection:
 kubeconfig: "/var/lib/kubernetes/kube-scheduler.kubeconfig"
leaderElection:
 leaderElect: true
EOF
```

`kube-scheduler.service`如下所示：

```
johndoe@kube-controller-1$ sudo cat << EOF | sudo tee /etc/systemd/system/kube-scheduler.service
[Unit]
Description=Kubernetes Scheduler
Documentation=https://github.com/kubernetes/kubernetes
[Service]
ExecStart=/usr/local/bin/kube-scheduler \\
 --config=/etc/kubernetes/config/kube-scheduler.yml \\
 --v=2
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
```

在继续下一步之前，重复在每个控制器节点上的*安装控制平面*部分中的所有步骤。

# 启动控制平面

在每个控制器节点上完成每个组件的安装后，我们准备启动和测试服务。

为此，首先使用以下命令启用和启动所有`systemd`单元：

```
johndoe@kube-controller-1$ sudo systemctl daemon-reload

johndoe@kube-controller-1$ sudo systemctl enable kube-apiserver kube-controller-manager kube-scheduler

johndoe@kube-controller-1$ sudo systemctl start kube-apiserver kube-controller-manager kube-scheduler

johndoe@kube-controller-1$ sudo systemctl status kube-apiserver kube-controller-manager kube-scheduler
```

最后，为了能够自己使用`kubectl`，我们需要设置要连接的集群的上下文，并将`kubeconfig`管理员设置为默认值。我们目前设置的`kubeconfig`管理员指向`localhost`作为`kube-apiserver`端点。这暂时没问题，因为我们只想测试我们的组件。

在`kube-controller-1`中输入以下命令：

```
johndoe@kube-controller-1$ mkdir /home/johndoe/.kube/

johndoe@kube-controller-1$ cat /home/johndoe/admin.kubeconfig > /home/johndoe/.kube/config

johndoe@kube-controller-1$ kubectl get cs
```

输出应如下所示：

```
NAME                       STATUS     MESSAGE              ERROR
controller-manager         Healthy     ok
scheduler                  Healthy     ok
etcd-0                     Healthy     {"health": "true"}
etcd-1                     Healthy     {"health": "true"}
etcd-2                     Healthy     {"health": "true"}
```

# 为 kubelets 设置 RBAC 权限。

我们的 API 服务器将需要权限与`kubelets` API 进行通信。为此，我们创建将绑定到 Kubernetes 用户的集群角色。我们将在一个控制器节点上执行此操作，因为我们将使用`kubectl`，并且更改将应用于整个集群。

# 集群角色

使用以下命令创建包含权限的集群角色：

```
johndoe@kube-controller-1$ cat << EOF | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1beta1
kind: ClusterRole
metadata:
 annotations:
 rbac.authorization.kubernetes.io/autoupdate: "true"
 labels:
 kubernetes.io/bootstrapping: rbac-defaults
 name: system:kube-apiserver-to-kubelet
rules:
 - apiGroups:
 - ""
 resources:
 - nodes/proxy
 - nodes/stats
 - nodes/log
 - nodes/spec
 - nodes/metrics
 verbs:
 - "*"
EOF
```

# 集群角色绑定

现在使用以下命令将角色绑定到 Kubernetes 用户：

```
johndoe@kube-controller-1$ cat << EOF | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1beta1
kind: ClusterRoleBinding
metadata:
 name: system:kube-apiserver
 namespace: ""
roleRef:
 apiGroup: rbac.authorization.k8s.io
 kind: ClusterRole
 name: system:kube-apiserver-to-kubelet
subjects:
 - apiGroup: rbac.authorization.k8s.io
 kind: User
 name: kubernetes
EOF
```

# 负载均衡器设置

我们需要将请求负载均衡到所有 kube-controller 节点。因为我们在云上运行，我们可以创建一个负载均衡器对象，该对象将在所有节点上负载均衡请求。不仅如此，我们还可以配置健康探测，以监视控制器节点的状态，看它们是否可用来接收请求。

# 创建负载均衡器

负载均衡器是我们一直在保存公共 IP 的地方。LB 将成为我们从外部访问集群的入口。我们需要创建规则来健康检查端口`80`，并将`kubectl`请求重定向到`6443`。

让我们按照以下步骤来实现这一点。

# Azure 负载均衡器

我们将不得不回到我们安装了 Azure CLI 的工作站，以完成接下来的一系列步骤。

在您的工作站上创建负载均衡器并为其分配公共 IP，请运行以下命令：

```
az network lb create -n kube-lb \
--sku Standard \
--public-ip-address kube-api-pub-ip
```

现在我们已经创建了负载均衡器，我们仍然需要配置三件事：

+   后端池

+   健康探测

+   负载均衡规则

# 后端池

到目前为止，我们一直在通过 Azure CLI 进行与 Azure 相关的一切。让我们通过 Azure 门户按照以下步骤，以便您也可以熟悉门户：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-arch/img/c8a39b26-0784-4a9b-aa82-9ce3e429b507.png)

要创建后端池，请转到 kube-lb 对象，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-arch/img/39e23280-0c2f-4e1a-a367-fe23bab0fb65.png)

当您在负载均衡器对象内时，请转到后端池并单击添加，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-arch/img/315ef824-ef98-4093-a4d4-ad9e97422f10.png)

当您单击“添加”时，将出现一个菜单。将您的后端池命名为`kube-lb-backend`，并确保选择所有 kube-controller 节点及其各自的 IP，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-arch/img/0fd2e97f-982e-4dbe-85ba-b52bb5428e03.png)

示例

单击“添加”以完成。我们已成功设置了后端 VM。

# 健康探测

在我们创建负载均衡规则之前，我们需要创建健康探测，告诉我们的 LB 哪些节点可以接收流量。因为在撰写本章时，Azure 中的负载均衡器不支持 HTTPS 健康探测，我们需要通过 HTTP 公开`/healthz`端点。为此，我们将在我们的控制节点上安装 Nginx，并将传入到端口`80`的代理请求传递到端口`6443`。

通过 SSH 返回到您的控制节点，并在每个节点上执行以下过程：

```
johndoe@kube-controller-1$ sudo yum install epel-release && yum install nginx
```

安装 Nginx 后，在`/etc/nginx/nginx.conf`中替换`server`条目为以下内容：

```
server {
 listen 80;
 server_name kubernetes.default.svc.cluster.local;

 location /healthz {
 proxy_pass https://127.0.0.1:6443/healthz;
 proxy_ssl_trusted_certificate /var/lib/kubernetes/ca.pem;
 }
}
```

因为我们正在运行基于 RHEL 的发行版，默认情况下启用了 SELINUX；因此，它将阻止 Nginx 访问端口`6443`上的 TCP 套接字。为了允许这种行为，我们需要运行以下命令。

首先，我们安装所需的软件包来管理 SELINUX，如下命令所示：

```
johndoe@kube-controller-1$ sudo yum install policycoreutils-python
```

安装软件包后，我们运行以下命令允许连接到端口`6443`：

```
johndoe@kube-controller-1$ sudo semanage port -a -t http_port_t -p tcp 6443
```

最后，我们使用以下命令启动`nginx`：

```
johndoe@kube-controller-1$ sudo systemctl daemon-reload && \
systemctl enable nginx --now
```

如果您想测试这个，您可以随时在`localhost`上运行`curl`，就像这样：

```
johndoe@kube-controller-1$ curl -v http://localhost/healthz
```

如果一切配置正确，将生成以下输出：

```
* About to connect() to localhost port 80 (#0)
*   Trying 127.0.0.1...
* Connected to localhost (127.0.0.1) port 80 (#0)
> GET /healthz HTTP/1.1
> User-Agent: curl/7.29.0
> Host: localhost
> Accept: */* < HTTP/1.1 200 OK
< Server: nginx/1.12.2
< Date: Sun, 28 Oct 2018 05:44:35 GMT
< Content-Type: text/plain; charset=utf-8
< Content-Length: 2
< Connection: keep-alive
<
* Connection #0 to host localhost left intact
Ok
```

请记住为每个控制节点重复所有这些过程。

现在健康端点已暴露，我们已准备好在负载均衡器中创建健康探测规则。

回到`kube-lb`菜单，在设置下，与我们配置后端池的地方相同，选择健康探测，然后单击“添加”。

菜单出现后，填写字段，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-arch/img/de036edf-e4cc-4d3a-b71a-0f471cff5621.png)

# 负载均衡规则

我们已经准备好创建负载均衡规则，并使我们的负载均衡器准备就绪。

该过程与我们在后端池和健康探测中使用的过程相同。转到 kube-lb 下的设置菜单，选择负载均衡规则。单击“添加”并填写出现的对话框，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-arch/img/ab7bfe68-f15c-4c60-a5d0-46072476d4bf.png)

一切准备就绪后，我们只需要打开我们的网络安全组，允许在端口`6443`上进行连接。

在 Azure CLI 工作站上运行以下命令以创建规则：

```
az network nsg rule create --nsg-name kube-nsg \
 -n pub_https_allow \
 --direction Inbound \
 --priority 110 \
 --access Allow \
 --description "Allow HTTPS" \
 --destination-address-prefixes '*' \
 --destination-port-ranges 6443 \
 --protocol Tcp \
 --source-address-prefixes '*' \
 --source-port-ranges '*' \
 --direction Inbound
```

等待几分钟生效，然后在浏览器中导航至`https://<LB_IP>:6443/version`。

您应该看到类似以下内容：

```
{
 "major": "1",
 "minor": "12",
 "gitVersion": "v1.12.0",
 "gitCommit": "0ed33881dc4355495f623c6f22e7dd0b7632b7c0",
 "gitTreeState": "clean",
 "buildDate": "2018-09-27T16:55:41Z",
 "goVersion": "go1.10.4",
 "compiler": "gc",
 "platform": "linux/amd64"
}
```

这将表明您可以通过 LB 访问 API 服务器。

# 工作节点设置

现在是配置和安装我们的工作节点的时候了。在这些节点上，我们将安装`kubelet`、kube 代理、容器运行时和容器网络接口插件。

从管理 VM 中的第一个工作节点 SSH 登录，如下命令所示：

```
johndoe@management-vm$ ssh johndoe@kube-node-1
```

# 下载和准备二进制文件

在配置任何服务之前，我们需要下载任何依赖项并设置所需的存储库。之后，我们可以开始下载二进制文件并将它们移动到它们各自的位置。

# 添加 Kubernetes 存储库

我们需要配置的存储库是 Kubernetes 存储库。通过这样，我们将能够下载`kubectl`。让我们使用以下命令设置：

```
johndoe@kube-node-1$ sudo cat << EOF > /etc/yum.repos.d/kubernetes.repo
[kubernetes]
name=Kubernetes
baseurl=https://packages.cloud.google.com/yum/repos/kubernetes-el7-x86_64
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=https://packages.cloud.google.com/yum/doc/yum-key.gpg https://packages.cloud.google.com/yum/doc/rpm-package-key.gpg
EOF
```

# 安装依赖项和 kubectl

通过配置`repo`，我们可以开始下载`kubectl`和我们将下载的二进制文件所需的任何依赖项。让我们使用以下命令设置：

```
johndoe@kube-node-1$ sudo yum install -y kubectl socat conntrack ipset libseccomp
```

# 下载和存储工作节点二进制文件

现在我们的依赖项准备好了，我们可以使用以下命令下载所需的工作节点二进制文件：

```
johndoe@kube-node-1$ wget \
https://github.com/kubernetes-sigs/cri-tools/releases/download/v1.12.0/crictl-v1.12.0-linux-amd64.tar.gz \
https://storage.googleapis.com/kubernetes-release/release/v1.12.0/bin/linux/amd64/kubelet \
https://github.com/containernetworking/plugins/releases/download/v0.6.0/cni-plugins-amd64-v0.6.0.tgz \
https://github.com/opencontainers/runc/releases/download/v1.0.0-rc5/runc.amd64 \
https://storage.googleapis.com/kubernetes-release/release/v1.12.0/bin/linux/amd64/kube-proxy \
https://github.com/containerd/containerd/releases/download/v1.1.2/containerd-1.1.2.linux-amd64.tar.gz
```

现在让我们使用以下命令创建最近下载的二进制文件的文件夹结构：

```
johndoe@kube-node-1$ sudo mkdir -p \
/etc/cni/net.d \
/opt/cni/bin \
/var/lib/kube-proxy \
/var/lib/kubelet \
/var/lib/kubernetes \
/var/run/kubernetes
```

我们将名称更改为`runc`以方便使用并符合约定，如以下命令所示：

```
johndoe@kube-node-1$ mv runc.amd64 runc
```

我们使用以下命令为其余的二进制文件授予可执行权限：

```
johndoe@kube-node-1$ chmod +x kube-proxy kubelet runc
```

给予它们可执行权限后，我们可以使用以下命令将它们移动到`/usr/local/bin/`：

```
johndoe@kube-node-1$ sudo mv kube-proxy kubelet runc /usr/local/bin/
```

一些下载的文件是 TAR 存档文件，我们需要使用以下命令`untar`并将其存储在各自的位置：

```
johndoe@kube-node-1$ tar xvzf crictl-v1.12.0-linux-amd64.tar.gz

johndoe@kube-node-1$ sudo mv crictl /usr/local/bin/

johndoe@kube-node-1$ sudo tar xvzf cni-plugins-amd64-v0.6.0.tgz -C /opt/cni/bin/

johndoe@kube-node-1$ tar xvzf containerd-1.1.2.linux-amd64.tar.gz

johndoe@kube-node-1$ sudo mv ./bin/* /bin/
```

# Containerd 设置

现在我们准备好开始配置每个服务了。第一个是`containerd`。

使用以下命令创建配置目录：

```
johndoe@kube-node-1$ sudo mkdir -p /etc/containerd/
```

现在我们创建`toml`配置文件，告诉`containerd`要使用哪个容器运行时。让我们使用以下命令进行设置：

```
johndoe@kube-node-1$ sudo cat << EOF | sudo tee /etc/containerd/config.toml
[plugins]
[plugins.cri.containerd]
snapshotter = "overlayfs"
[plugins.cri.containerd.default_runtime]
runtime_type = "io.containerd.runtime.v1.linux"
runtime_engine = "/usr/local/bin/runc"
runtime_root = ""
EOF
```

最后，让我们使用以下命令设置`systemd`单元文件：

```
johndoe@kube-node-1$ sudo cat << EOF | sudo tee /etc/systemd/system/containerd.service
[Unit]
Description=containerd container runtime
Documentation=https://containerd.io
After=network.target

[Service]
ExecStartPre=/sbin/modprobe overlay
ExecStart=/bin/containerd
Restart=always
RestartSec=5
Delegate=yes
KillMode=process
OOMScoreAdjust=-999
LimitNOFILE=1048576
LimitNPROC=infinity
LimitCORE=infinity

[Install]
WantedBy=multi-user.target
EOF
```

# kubelet

我们工作节点中的主要服务是`kubelet`。让我们创建它的配置文件。

首先，我们需要使用以下命令将`kubelet`证书移动到它们的位置：

```
johndoe@kube-node-1$ sudo mv /home/johndoe/${HOSTNAME}-key.pem /home/johndoe/${HOSTNAME}.pem /var/lib/kubelet/

johndoe@kube-node-1$ sudo mv /home/johndoe/${HOSTNAME}.kubeconfig /var/lib/kubelet/kubeconfig

johndoe@kube-node-1$ sudo mv /home/johndoe/ca.pem /var/lib/kubernetes/
```

现在我们创建 YAML 配置文件，其中包含 DNS 服务器 IP 地址、集群域和证书文件的位置等内容。让我们使用以下命令进行设置：

```
johndoe@kube-node-1$ sudo cat << EOF | sudo tee /var/lib/kubelet/kubelet-config.yaml
kind: KubeletConfiguration
apiVersion: kubelet.config.k8s.io/v1beta1
authentication:
 anonymous:
 enabled: false
 webhook:
 enabled: true
 x509:
 clientCAFile: "/var/lib/kubernetes/ca.pem"
authorization:
 mode: Webhook
clusterDomain: "cluster.local"
clusterDNS: 
 - "10.20.0.10"
runtimeRequestTimeout: "15m"
tlsCertFile: "/var/lib/kubelet/${HOSTNAME}.pem"
tlsPrivateKeyFile: "/var/lib/kubelet/${HOSTNAME}-key.pem"
EOF
```

最后，我们使用以下命令创建服务单元文件：

```
johndoe@kube-node-1$ sudo cat << EOF | sudo tee /etc/systemd/system/kubelet.service
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
 --v=2 \\
 --hostname-override=${HOSTNAME} \\
 --allow-privileged=true
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
```

# kube-proxy

下一个要创建的服务是`kube-proxy`。

我们使用以下命令移动先前创建的`kubeconfigs`：

```
johndoe@kube-node-1$ sudo mv /home/johndoe/kube-proxy.kubeconfig /var/lib/kube-proxy/kubeconfig
```

与`kubelet`一样，`kube-proxy`还需要一个配置`YAML`，其中包含集群 CIDR 和`kube-proxy`将运行的模式。让我们使用以下命令进行设置：

```
johndoe@kube-node-1$ sudo cat << EOF | sudo tee /var/lib/kube-proxy/kube-proxy-config.yaml
kind: KubeProxyConfiguration
apiVersion: kubeproxy.config.k8s.io/v1alpha1
clientConnection:
 kubeconfig: "/var/lib/kube-proxy/kubeconfig"
mode: "iptables"
clusterCIDR: "10.30.0.0/16"
EOF
```

最后，我们使用以下命令为`kube-proxy`创建一个单元文件：

```
johndoe@kube-node-1$ sudo cat << EOF | sudo tee /etc/systemd/system/kube-proxy.service
[Unit]
Description=Kubernetes Kube Proxy
Documentation=https://github.com/kubernetes/kubernetes

[Service]
ExecStart=/usr/local/bin/kube-proxy \\
 --config=/var/lib/kube-proxy/kube-proxy-config.yaml
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
```

# 启动服务

完成所有 kube 节点上的这些步骤后，您可以使用以下命令在每个节点上启动服务：

```
johndoe@kube-node-1$ sudo systemctl daemon-reload && \
systemctl enable containerd kubelet kube-proxy && \
systemctl start containerd kubelet kube-proxy && \
systemctl status containerd kubelet kube-proxy
```

# Kubernetes 网络

在我们的集群中还有一些事情要做：我们需要安装网络提供程序并配置 DNS。

# 准备节点

我们的节点必须能够转发数据包，以便我们的 pod 能够与外部世界通信。Azure VM 默认情况下未启用 IP 转发，因此我们必须手动启用它。

为此，请转到 Azure CLI 工作站并运行以下命令：

```
for i in 1 2; do 
az network nic update \
-n $(az vm show --name kube-node-${i} --query [networkProfile.networkInterfaces[*].id] --output tsv | sed 's:.*/::') \
--ip-forwarding true
done
```

这将在 VM 的 NIC 上启用 IP 转发功能。

现在我们必须在工作节点上启用 IP 转发内核参数。

从管理 VM 登录到每个工作节点，并使用以下命令启用 IPv4 转发：

```
johndoe@kube-node-1$ sudo sysctl net.ipv4.conf.all.forwarding=1

johndoe@kube-node-1$ sudo echo "net.ipv4.conf.all.forwarding=1" | tee -a /etc/sysctl.conf
```

# 配置远程访问

现在，为了从管理 VM 运行`kubectl`命令，我们需要创建一个使用集群的管理员证书和公共 IP 地址的`kubeconfig`。让我们使用以下命令进行设置：

```
johndoe@management-vm$ kubectl config set-cluster kube \
 --certificate-authority=/home/johndoe/certs/ca.pem \
 --embed-certs=true \
 --server=https://104.45.174.96:6443

johndoe@management-vm$ kubectl config set-credentials admin \
 --client-certificate=/home/johndoe/certs/admin/admin.pem \
 --client-key=~/certs/admin/admin-key.pem

johndoe@management-vm$ kubectl config set-context kube \
 --cluster=kube \
 --user=admin

johndoe@management-vm$ kubectl config use-context kube
```

# 安装 Weave Net

配置了管理 VM 上的远程访问后，我们现在可以在不必登录到控制节点的情况下运行`kubectl`命令。

要安装 Weave Net，请从管理 VM 运行以下`kubectl`命令：

```
johndoe@management-vm$ kubectl apply -f "https://cloud.weave.works/k8s/net?k8s-version=$(kubectl version | base64 | tr -d '\n')&env.IPALLOC_RANGE=10.30.0.0/16"
```

安装了 Weave Net 后，现在我们的 pod 将有 IP 分配。

# DNS 服务器

现在我们将配置我们的 DNS 服务器，它将由 Core DNS 提供，这是一个基于插件的开源 DNS 服务器。让我们使用以下命令进行设置：

```
johndoe@management-vm$ kubectl create -f https://raw.githubusercontent.com/dsalamancaMS/CoreDNSforKube/master/coredns.yaml
```

使用以下命令检查 DNS pod：

```
johndoe@management-vm$  kubectl get pods -n kube-system
```

创建了 DNS 服务器 pod 后，我们已成功完成了 Kubernetes 集群的安装。如果您愿意，您可以创建以下部署来再次测试集群：

```
apiVersion: apps/v1
kind: Deployment
metadata:
 name: nginx-deployment
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
 image: nginx:1.7.9
 ports:
 - containerPort: 80
```

现在我们已经看到了从头开始创建集群所需的步骤，我想谈谈托管的 Kubernetes 解决方案。

# 在云上管理 Kubernetes

像你在本章中看到的那样，安装和使 Kubernetes 集群可用并为生产做好准备是一个非常漫长和复杂的过程。如果有任何一步出错，您的整个部署可能会变得毫无意义。因此，许多云提供商提供了托管的 Kubernetes 解决方案——以某种方式作为服务的 Kubernetes。在这种托管解决方案中，云提供商或服务提供商将管理集群的主节点，其中包括所有 Kubernetes 控制器、API 服务器，甚至`etcd`数据库。这是一个重大优势，因为使用托管服务意味着您不必担心主节点的维护，因此您不必担心以下问题：

+   更新 SSL 证书

+   更新/升级`etcd`数据库

+   更新/升级每个主节点二进制文件

+   向集群注册额外节点

+   如果出现问题，缺乏支持

+   与云基础设施的透明集成

+   操作系统补丁和维护

通过忘记这些，我们可以专注于重要的事情，比如在我们的集群上配置 pod 和创建工作负载。有了托管服务，学习曲线大大降低，因为我们的员工可以主要专注于 Kubernetes 的功能，而不是它的工作原理，以便他们维护它。

在撰写本文时，一些值得一提的托管 Kubernetes 服务来自以下三个最大的云提供商：

+   Azure Kubernetes 服务（AKS）

+   亚马逊网络服务弹性容器服务（EKS）

+   谷歌 Kubernetes 引擎（GKE）

除了托管的 Kubernetes 服务外，还有几个基于 Kubernetes 的开源项目和非开源项目。这些项目并非完全托管，而是在后台使用 Kubernetes 来实现其目标。以下是一些更知名的项目：

+   Okd（红帽 OpenShift 的上游社区项目）

+   红帽 OpenShift

+   SUSE 容器即服务（Caas）平台

+   Mesosphere Kubernetes 引擎

# 总结

在本章中，我们学习了配置 Kubernetes 集群的基本步骤。我们还了解了 Azure 命令行界面以及如何在 Azure 中配置资源。我们还尝试了整个部署过程中的不同工具，如 CFSSL 和 Nginx。

我们学习了并配置了`kubectl`配置文件，使我们能够访问我们的集群，并部署了一个虚拟部署来测试我们的集群。最后，我们看了运行托管集群的好处以及主要公共云提供商中可以找到的不同类型的托管服务。

下一章将解释每个组件的作用。读者将了解不同组件及其目的。

# 问题

1.  如何安装 Kubernetes？

1.  什么是`kubeconfig`？

1.  我们如何创建 SSL 证书？

1.  什么是 AKS？

1.  我们如何使用 Azure CLI？

1.  我们如何在 Azure 中配置资源组？

1.  我们如何安装`etcd`？

# 进一步阅读

+   Packt Publishing 的《精通 Kubernetes》：[`prod.packtpub.com/in/application-development/mastering-kubernetes-second-edition`](https://prod.packtpub.com/in/application-development/mastering-kubernetes-second-edition)

+   Packt Publishing 的《面向开发人员的 Kubernetes》：[`prod.packtpub.com/in/virtualization-and-cloud/kubernetes-developers`](https://prod.packtpub.com/in/virtualization-and-cloud/kubernetes-developers)

+   Packt Publishing 的《使用 Kubernetes 进行微服务实践》：[`prod.packtpub.com/in/virtualization-and-cloud/hands-microservices-kubernetes`](https://prod.packtpub.com/in/virtualization-and-cloud/hands-microservices-kubernetes)

# 参考文献/来源：

+   生成自签名证书：[`coreos.com/os/docs/latest/generate-self-signed-certificates.html`](https://coreos.com/os/docs/latest/generate-self-signed-certificates.html)

+   CloudFlare 的 PKI/TLS 工具包：[`github.com/cloudflare/cfssl`](https://github.com/cloudflare/cfssl)

+   **Go 编程语言**：[`golang.org/doc/install`](https://golang.org/doc/install)
