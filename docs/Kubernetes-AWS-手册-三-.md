# Kubernetes AWS 手册（三）

> 原文：[`zh.annas-archive.org/md5/9CADC322D770A4D3AD0027E7CB5CC592`](https://zh.annas-archive.org/md5/9CADC322D770A4D3AD0027E7CB5CC592)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：抱歉，我的应用程序吃掉了集群

使用 Kubernetes 运行我们的应用程序可以使我们在集群中的机器上实现更高的资源利用率。Kubernetes 调度程序非常有效地将不同的应用程序打包到您的集群中，以最大程度地利用每台机器上的资源。您可以安排一些低优先级的作业，如果需要可以重新启动，例如批处理作业，以及高优先级的作业，例如 Web 服务器或数据库。Kubernetes 将帮助您利用空闲的 CPU 周期，这些周期发生在您的 Web 服务器等待请求时。

如果您想减少在 AWS 上支付的 EC2 实例的费用来运行您的应用程序，这是个好消息。学会如何配置您的 Pod 是很重要的，这样 Kubernetes 可以核算您的应用程序的资源使用情况。如果您没有正确配置您的 Pod，那么您的应用程序的可靠性和性能可能会受到影响，因为 Kubernetes 可能需要从节点中驱逐您的 Pod，因为资源不足。

在本章中，您将首先学习如何核算 Pod 将使用的内存和 CPU。我们将学习如何配置具有不同服务质量的 Pod，以便重要的工作负载能够保证它们所需的资源，但不太重要的工作负载可以在有空闲资源时使用，而无需专用资源。您还将学习如何利用 Kubernetes 自动缩放功能，在负载增加时向您的应用程序添加额外的 Pod，并在资源不足时向您的集群添加额外的节点。

在本章中，您将学习如何执行以下操作：

+   配置容器资源请求和限制

+   为所需的**服务质量**（**QoS**）类别配置您的 Pod

+   设置每个命名空间资源使用的配额

+   使用水平 Pod 自动缩放器自动调整您的应用程序，以满足对它们的需求

+   使用集群自动缩放器根据集群随时间变化的使用情况自动提供和终止 EC2 实例

# 资源请求和限制

Kubernetes 允许我们通过将多个不同的工作负载调度到一组机器中来实现集群的高利用率。每当我们要求 Kubernetes 调度一个 Pod 时，它需要考虑将其放置在哪个节点上。如果我们可以给调度器一些关于 Pod 所需资源的信息，它就可以更好地决定在哪个节点上放置 Pod。然后它可以计算每个节点上的当前工作负载，并选择符合我们 Pod 预期资源使用的节点。我们可以选择使用资源**请求**向 Kubernetes 提供这些信息。请求在将 Pod 调度到节点时考虑。请求不会对 Pod 在特定节点上运行时可能消耗的资源量提供任何限制，它们只是代表我们，集群操作员，在要求将特定 Pod 调度到集群时所做的请求的记录。

为了防止 Pod 使用超过其应该的资源，我们可以设置资源**限制**。这些限制可以由容器运行时强制执行，以确保 Pod 不会使用超过所需资源的数量。

我们可以说，容器的 CPU 使用是可压缩的，因为如果我们限制它，可能会导致我们的进程运行更慢，但通常不会造成其他不良影响，而容器的内存使用是不可压缩的，因为如果容器使用超过其内存限制，唯一的补救措施就是杀死相关的容器。

向 Pod 规范添加资源限制和请求的配置非常简单。在我们的清单中，每个容器规范都可以有一个包含请求和限制的`resources`字段。在这个例子中，我们请求分配 250 MiB 的 RAM 和四分之一的 CPU 核心给一个 Nginx web 服务器容器。因为限制设置得比请求高，这允许 Pod 使用高达半个 CPU 核心，并且只有在内存使用超过 128 Mi 时才会杀死容器：

```
apiVersion: v1 
kind: Pod 
metadata: 
  name: webserver 
spec: 
  containers: 
  - name: nginx 
    image: nginx 
    resources: 
      limits: 
        memory: 128Mi 
        cpu: 500m 
      requests:
```

```
        memory: 64Mi 
        cpu: 250m 
```

# 资源单位

每当我们指定 CPU 请求或限制时，我们都是以 CPU 核心为单位进行指定。因为我们经常希望请求或限制 Pod 使用整个 CPU 核心的一部分，我们可以将这部分 CPU 指定为小数或毫核值。例如，值为 0.5 表示半个核心。还可以使用毫核值配置请求或限制。由于 1,000 毫核等于一个核心，我们可以将一半 CPU 指定为 500 m。可以指定的最小 CPU 量为 1 m 或 0.001。

我发现在清单中使用毫核单位更易读。当使用`kubectl`或 Kubernetes 仪表板时，您还会注意到 CPU 限制和请求以毫核值格式化。但是，如果您正在使用自动化流程创建清单，您可能会使用浮点版本。

内存的限制和请求以字节为单位。但在清单中以这种方式指定它们会非常笨拙且难以阅读。因此，Kubernetes 支持用于引用字节的倍数的标准前缀；您可以选择使用十进制乘数，如 M 或 G，或者其中一个二进制等效项，如 Mi 或 Gi，后者更常用，因为它们反映了物理 RAM 的实际大小。

这些单位的二进制版本实际上是大多数人在谈论兆字节或千兆字节时真正意味着的，尽管更正确的说法是他们在谈论兆比字节和吉比字节！

在实践中，您应该始终记住使用末尾带有**i**的单位，否则您将得到比预期少一些的内存。这种表示法是在 1998 年引入 ISO/IEC 80000 标准中的，以避免十进制和二进制单位之间的混淆。

| **十进制** | **二进制** |
| --- | --- |
| **名称** | **字节** | **后缀** | **名称** | **字节** | **后缀** |
| 千字节 | 1000 | K | 基比字节 | 1024 | Ki |
| 兆字节 | 1000² | M | 兆比字节 | 1024² | Mi |
| 吉字节 | 1000³ | G | 吉比字节 | 1024³ | Gi |
| 太字节 | 1000⁴ | T | 泰比字节 | 1024⁴ | Ti |
| 皮字节 | 1000⁵ | P | 皮比字节 | 1024⁵ | Pi |
| 艾字节 | 1000⁶ | E | 艾比字节 | 1024⁶ | Ei |

Kubernetes 支持的内存单位

# 如何管理具有资源限制的 Pods

当 Kubelet 启动容器时，CPU 和内存限制将传递给容器运行时，然后容器运行时负责管理该容器的资源使用。

如果您正在使用 Docker，CPU 限制（以毫核为单位）将乘以 100，以确定容器每 100 毫秒可以使用的 CPU 时间。如果 CPU 负载过重，一旦容器使用完其配额，它将不得不等到下一个 100 毫秒周期才能继续使用 CPU。

在 cgroups 中运行的不同进程之间共享 CPU 资源的方法称为**完全公平调度器**或**CFS**；这通过在不同的 cgroups 之间分配 CPU 时间来实现。这通常意味着为一个 cgroup 分配一定数量的时间片。如果一个 cgroup 中的进程处于空闲状态，并且没有使用其分配的 CPU 时间，这些份额将可供其他 cgroup 中的进程使用。

这意味着一个 pod 即使限制设置得太低，可能仍然表现良好，但只有在另一个 pod 开始占用其公平份额的 CPU 后，它才可能突然停止。您可能会发现，如果您在空集群上开始为您的 pod 设置 CPU 限制，并添加额外的工作负载，您的 pod 的性能会开始受到影响。

在本章的后面，我们将讨论一些基本的工具，可以让我们了解每个 pod 使用了多少 CPU。

如果内存限制达到，容器运行时将终止容器（并可能重新启动）。如果容器使用的内存超过请求的数量，那么当节点开始内存不足时，它就成为被驱逐的候选者。

# 服务质量（QoS）

当 Kubernetes 创建一个 pod 时，它被分配为三个 QoS 类别之一。这些类别用于决定 Kubernetes 如何在节点上调度和驱逐 pod。广义上讲，具有保证 QoS 类别的 pod 将受到最少的驱逐干扰，而具有 BestEffort QoS 类别的 pod 最有可能受到干扰：

+   **保证**：这适用于高优先级的工作负载，这些工作负载受益于尽可能避免从节点中被驱逐，并且对于 CPU 资源具有比较低 QoS 类别的 pod 的优先级，容器运行时保证在需要时将提供指定限制中的全部 CPU 数量。

+   **可突发**: 这适用于较不重要的工作负载，例如可以在可用时利用更多 CPU 的后台作业，但只保证 CPU 请求中指定的级别。当节点资源不足时，可突发的 pod 更有可能被从节点中驱逐，特别是如果它们使用的内存超过了请求的数量。

+   **BestEffort**: 具有此类别的 pod 在节点资源不足时最有可能被驱逐。此 QoS 类别中的 pod 也只能使用节点上空闲的 CPU 和内存，因此如果节点上运行的其他 pod 正在大量使用 CPU，这些 pod 可能会完全被资源耗尽。如果您在此类别中调度 Pods，您应确保您的应用在资源匮乏和频繁重启时表现如预期。

实际上，最好避免使用具有 BestEffort QoS 类别的 pod，因为当集群负载过重时，这些 pod 将受到非常不寻常的行为影响。

当我们在 pod 的容器中设置资源和请求限制时，这些值的组合决定了 pod 所在的 QoS 类别。

要被赋予 BestEffort 的 QoS 类别，pod 中的任何容器都不应该设置任何 CPU 或内存请求或限制：

```
apiVersion: v1 
kind: Pod 
metadata: 
  name: best-effort 
spec: 
  containers: 
  - name: nginx 
    image: nginx 
```

一个没有资源限制或请求的 pod 将被分配 BestEffort 的 QoS 类别。

要被赋予保证的 QoS 类别，pod 需要在 pod 中的每个容器上都设置 CPU 和内存请求和限制。限制和请求必须相匹配。作为快捷方式，如果一个容器只设置了其限制，Kubernetes 会自动为资源请求分配相等的值：

```
apiVersion: v1 
kind: Pod 
metadata: 
  name: guaranteed 
spec: 
  containers: 
  - name: nginx 
    image: nginx 
    resources: 
      limits: 
        memory: 256Mi 
        cpu: 500m 
```

一个将被分配保证的 QoS 类别的 pod。

任何介于这两种情况之间的情况都将被赋予可突发的 QoS 类别。这适用于任何设置了任何 pod 的 CPU 或内存限制或请求的 pod。但是如果它们不符合保证类别的标准，例如没有在每个容器上设置限制，或者请求和限制不匹配：

```
apiVersion: v1 
kind: Pod 
metadata: 
  name: burstable 
spec: 
  containers: 
  - name: nginx 
    image: nginx 
    resources: 
      limits: 
        memory: 256Mi 
        cpu: 500m 
      requests: 
        memory: 128Mi 
        cpu: 250m 
```

一个将被分配可突发的 QoS 类别的 pod。

# 资源配额

资源配额允许您限制特定命名空间可以使用多少资源。根据您在组织中选择使用命名空间的方式，它们可以为您提供一种强大的方式，限制特定团队、应用程序或一组应用程序使用的资源，同时仍然让开发人员有自由调整每个单独容器的资源限制。

资源配额是一种有用的工具，当您想要控制不同团队或应用程序的资源成本，但仍希望实现将多个工作负载调度到同一集群的利用率时。

在 Kubernetes 中，资源配额由准入控制器管理。该控制器跟踪诸如 Pod 和服务之类的资源的使用，如果超出限制，它将阻止创建新资源。

资源配额准入控制器由在命名空间中创建的一个或多个 `ResourceQuota` 对象配置。这些对象通常由集群管理员创建，但您可以将创建它们整合到您组织中用于分配资源的更广泛流程中。

让我们看一个示例，说明配额如何限制集群中 CPU 资源的使用。由于配额将影响命名空间中的所有 Pod，因此我们将从使用 `kubectl` 创建一个新的命名空间开始：

```
$ kubectl create namespace quota-example
namespace/quota-example created  
```

我们将从创建一个简单的示例开始，确保每个新创建的 Pod 都设置了 CPU 限制，并且总限制不超过两个核心：

```
apiVersion: v1 
kind: ResourceQuota 
metadata: 
  name: resource-quota 
  namespace: quota-example 
spec: 
  hard: 
    limits.cpu: 2 
```

通过使用 `kubectl` 将清单提交到集群来创建 `ResourceQuota`。

一旦在命名空间中创建了指定资源请求或限制的 `ResourceQuota`，则在创建之前，所有 Pod 必须指定相应的请求或限制。

为了看到这种行为，让我们在我们的命名空间中创建一个示例部署：

```
apiVersion: apps/v1 
kind: Deployment 
metadata: 
  name: example 
  namespace: quota-example 
spec: 
  selector: 
    matchLabels: 
      app: example 
  template: 
    metadata: 
      labels: 
        app: example 
    spec: 
      containers: 
      - name: nginx 
        image: nginx 
        resources: 
          limits: 
            cpu: 500m 
```

一旦您使用 `kubectl` 将部署清单提交给 Kubernetes，请检查 Pod 是否正在运行：

```
$ kubectl -n quota-example get pods
NAME                      READY     STATUS    RESTARTS   AGE
example-fb556779d-4bzgd   1/1       Running   0          1m  
```

现在，扩展部署并观察是否创建了额外的 Pod：

```
$ kubectl -n quota-example scale deployment/example --replicas=4$ kubectl -n quota-example get pods
NAME                      READY     STATUS    RESTARTS   AGE
example-fb556779d-4bzgd   1/1       Running   0          2m
example-fb556779d-bpxm8   1/1       Running   0          1m
example-fb556779d-gkbvc   1/1       Running   0          1m
example-fb556779d-lcrg9   1/1       Running   0          1m  
```

因为我们指定了 `500m` 的 CPU 限制，所以将部署扩展到四个副本没有问题，这使用了我们在配额中指定的两个核心。

但是，如果您现在尝试扩展部署，使其使用的资源超出配额中指定的资源，您将发现 Kubernetes 不会安排额外的 Pod：

```
$ kubectl -n quota-example scale deployment/example --replicas=5  
```

运行`kubectl get events`将显示一个消息，其中调度程序未能创建满足副本计数所需的额外 pod：

```
$ kubectl -n quota-example get events
...
Error creating: pods "example-fb556779d-xmsgv" is forbidden: exceeded quota: resource-quota, requested: limits.cpu=500m, used: limits.cpu=2, limited: limits.cpu=2  
```

# 默认限制

当您在命名空间上使用配额时，一个要求是命名空间中的每个容器必须定义资源限制和请求。有时，这个要求可能会导致复杂性，并使在 Kubernetes 上快速工作变得更加困难。正确指定资源限制是准备应用程序投入生产的重要部分，但是，例如，在使用 Kubernetes 作为开发或测试工作负载的平台时，这确实增加了额外的开销。

Kubernetes 提供了在命名空间级别提供默认请求和限制的功能。您可以使用这个功能为特定应用程序或团队使用的命名空间提供一些合理的默认值。

我们可以使用`LimitRange`对象为命名空间中的容器配置默认限制和请求。这个对象允许我们为 CPU 或内存，或两者都提供默认值。如果一个命名空间中存在一个`LimitRange`对象，那么任何没有在`LimitRange`中配置资源请求或限制的容器将从限制范围中继承这些值。

有两种情况下，当创建一个 pod 时，`LimitRange`会影响资源限制或请求：

+   没有资源限制或请求的容器将从`LimitRange`对象继承资源限制和请求

+   没有资源限制但有指定请求的容器将从`LimitRange`对象中继承资源限制

如果容器已经定义了限制和请求，那么`LimitRange`将不起作用。因为只指定了限制的容器会将请求字段默认为相同的值，它们不会从`LimitRange`继承请求值。让我们看一个快速示例。我们首先创建一个新的命名空间：

```
$ kubectl create namespace limit-example
namespace/limit-example created  
```

创建限制范围对象的清单，并使用`kubectl`将其提交到集群中：

```
apiVersion: v1 
kind: LimitRange 
metadata: 
  name: example 
  namespace: limit-example 
spec: 
  limits: 
  - default: 
      memory: 512Mi 
      cpu: 1 
    defaultRequest: 
      memory: 256Mi 
      cpu: 500m 
    type: Container 
```

如果您在此命名空间中创建一个没有资源限制的 pod，它将在创建时从限制范围对象中继承：

```
$ kubectl -n limit-example run --image=nginx example  
```

`deployment.apps/`示例已创建。

您可以通过运行`kubectl describe`来检查限制：

```
$ kubectl -n limit-example describe pods 
... 
    Limits: 
      cpu:     1 
      memory:  512Mi 
    Requests: 
      cpu:        500m 
      memory:     256Mi 
... 
```

# 水平 Pod 自动缩放

一些应用程序可以通过添加额外的副本来扩展以处理增加的负载。无状态的 Web 应用程序就是一个很好的例子，因为添加额外的副本提供了处理对应用程序的增加请求所需的额外容量。一些其他应用程序也设计成可以通过添加额外的 pod 来处理增加的负载；许多围绕从中央队列处理消息的系统也可以以这种方式处理增加的负载。

当我们使用 Kubernetes 部署来部署我们的 pod 工作负载时，使用 `kubectl scale` 命令简单地扩展应用程序使用的副本数量。然而，如果我们希望我们的应用程序自动响应其工作负载的变化并根据需求进行扩展，那么 Kubernetes 为我们提供了水平 Pod 自动缩放。

水平 Pod 自动缩放允许我们定义规则，根据 CPU 利用率和其他自定义指标，在我们的部署中扩展或缩减副本的数量。在我们的集群中使用水平 Pod 自动缩放之前，我们需要部署 Kubernetes 度量服务器；该服务器提供了用于发现应用程序生成的 CPU 利用率和其他指标的端点。

# 部署度量服务器

在我们可以使用水平 Pod 自动缩放之前，我们需要将 Kubernetes 度量服务器部署到我们的集群中。这是因为水平 Pod 自动缩放控制器使用 `metrics.k8s.io` API 提供的指标，而这些指标是由度量服务器提供的。

虽然一些 Kubernetes 的安装可能默认安装此附加组件，在我们的 EKS 集群中，我们需要自己部署它。

有许多方法可以部署附加组件到您的集群中：

+   如果您遵循了第七章中的建议，*一个生产就绪的集群*，并且正在使用 Terraform 为您的集群进行配置，您可以像我们在第七章中配置 kube2iam 时一样，使用 `kubectl` 部署所需的清单。

+   如果您正在使用 helm 管理集群上的应用程序，您可以使用 stable/metrics server 图表。

+   在这一章中，为了简单起见，我们将使用 `kubectl` 部署度量服务器清单。

+   我喜欢将部署诸如指标服务器和 kube2iam 等附加组件集成到配置集群的过程中，因为我认为它们是集群基础设施的组成部分。但是，如果您要使用类似 helm 的工具来管理在集群上运行的应用程序的部署，那么您可能更喜欢使用相同的工具来管理在集群上运行的所有内容。您所做的决定取决于您和您的团队为管理集群及其上运行的应用程序采用的流程。

+   指标服务器是在 GitHub 存储库中开发的，网址为[`github.com/kubernetes-incubator/metrics-server`](https://github.com/kubernetes-incubator/metrics-server)。您将在该存储库的 deploy 目录中找到部署所需的清单。

首先从 GitHub 克隆配置。指标服务器从版本 0.0.3 开始支持 EKS 提供的身份验证方法，因此请确保您使用的清单至少使用该版本。

您将在`deploy/1.8+`目录中找到许多清单。`auth-reader.yaml`和`auth-delegator.yaml`文件配置了指标服务器与 Kubernetes 授权基础设施的集成。`resource-reader.yaml`文件配置了一个角色，以赋予指标服务器从 API 服务器读取资源的权限，以便发现 Pod 所在的节点。基本上，`metrics-server-deployment.yaml`和`metrics-server-service.yaml`定义了用于运行服务本身的部署，以及用于访问该服务的服务。最后，`metrics-apiservice.yaml`文件定义了一个`APIService`资源，将 metrics.k8s.io API 组注册到 Kubernetes API 服务器聚合层；这意味着对于 metrics.k8s.io 组的 API 服务器请求将被代理到指标服务器服务。

使用`kubectl`部署这些清单很简单，只需使用`kubectl apply`将所有清单提交到集群：

```
$ kubectl apply -f deploy/1.8+  
```

您应该看到关于在集群上创建的每个资源的消息。

如果您使用类似 Terraform 的工具来配置集群，您可以在创建集群时使用它来提交指标服务器的清单。

# 验证指标服务器和故障排除

在我们继续之前，我们应该花一点时间检查我们的集群和指标服务器是否正确配置以共同工作。

在度量服务器在您的集群上运行并有机会从集群中收集度量数据（给它一分钟左右的时间）之后，您应该能够使用`kubectl top`命令来查看集群中 pod 和节点的资源使用情况。

首先运行`kubectl top nodes`。如果您看到像这样的输出，那么度量服务器已经正确配置，并且正在从您的节点收集度量数据：

```
$ kubectl top nodes
NAME             CPU(cores)   CPU%      MEMORY(bytes)   MEMORY%
ip-10-3-29-209   20m          1%        717Mi           19%
ip-10-3-61-119   24m          1%        1011Mi          28%  
```

如果您看到错误消息，那么有一些故障排除步骤可以遵循。

您应该从描述度量服务器部署并检查一个副本是否可用开始：

```
kubectl -n kube-system describe deployment metrics-server  
```

如果没有配置正确，您应该通过运行`kubectl -n kube-system describe pod`来调试创建的 pod。查看事件，看看服务器为什么不可用。确保您至少运行版本 0.0.3 的度量服务器，因为之前的版本不支持与 EKS API 服务器进行身份验证。

如果度量服务器正在正确运行，但在运行`kubectl top`时仍然看到错误，问题可能是聚合层注册的 APIservice 没有正确配置。在运行`kubectl describe apiservice v1beta1.metrics.k8s.io`时，检查底部返回的信息中的事件输出。

一个常见的问题是，EKS 控制平面无法连接到端口`443`上的度量服务器服务。如果您遵循了第七章中的说明，*一个生产就绪的集群*，您应该已经有一个安全组规则允许控制平面到工作节点的流量，但一些其他文档可能建议更严格的规则，这可能不允许端口`443`上的流量。

# 根据 CPU 使用率自动扩展 pod

一旦度量服务器安装到我们的集群中，我们将能够使用度量 API 来检索有关集群中 pod 和节点的 CPU 和内存使用情况的信息。使用`kubectl top`命令就是一个简单的例子。

水平 Pod 自动缩放器也可以使用相同的度量 API 来收集组成部署的 pod 的当前资源使用情况的信息。

让我们来看一个例子；我们将部署一个使用大量 CPU 的示例应用程序，然后配置一个水平 Pod 自动缩放器，在 CPU 利用率超过目标水平时扩展该 pod 的额外副本，以提供额外的容量。

我们将部署的示例应用程序是一个简单的 Ruby Web 应用程序，可以计算斐波那契数列中的第 n 个数字，该应用程序使用简单的递归算法，效率不是很高（非常适合我们进行自动缩放实验）。该应用程序的部署非常简单。设置 CPU 资源限制非常重要，因为目标 CPU 利用率是基于此限制的百分比：

```
deployment.yaml 
apiVersion: apps/v1 
kind: Deployment 
metadata: 
  name: fib 
  labels: 
    app: fib 
spec: 
  selector: 
    matchLabels: 
      app: fib 
  template: 
    metadata: 
      labels: 
        app: fib 
    spec: 
      containers: 
      - name: fib 
        image: errm/fib 
        ports: 
        - containerPort: 9292 
        resources: 
          limits: 
            cpu: 250m 
            memory: 32Mi 
```

我们没有在部署规范中指定副本的数量；因此，当我们首次将此部署提交到集群时，副本的数量将默认为 1。这是创建部署的良好实践，我们打算通过 Horizontal Pod Autoscaler 调整副本的数量，因为这意味着如果我们稍后使用`kubectl apply`来更新部署，我们不会覆盖水平 Pod Autoscaler 设置的副本值（无意中缩减或增加部署）。

让我们将这个应用程序部署到集群中：

```
kubectl apply -f deployment.yaml  
```

您可以运行`kubectl get pods -l app=fib`来检查应用程序是否正确启动。

我们将创建一个服务，以便能够访问部署中的 Pod，请求将被代理到每个副本，分散负载：

```
service.yaml 
kind: Service 
apiVersion: v1 
metadata: 
  name: fib 
spec: 
  selector: 
    app: fib 
  ports: 
  - protocol: TCP 
    port: 80 
    targetPort: 9292 
```

使用`kubectl`将服务清单提交到集群：

```
kubectl apply -f service.yaml  
```

我们将配置一个 Horizontal Pod Autoscaler 来控制部署中副本的数量。`spec`定义了我们希望自动缩放器的行为；我们在这里定义了我们希望自动缩放器维护应用程序的 1 到 10 个副本，并实现 60%的目标平均 CPU 利用率。

当 CPU 利用率低于 60%时，自动缩放器将调整目标部署的副本计数；当超过 60%时，将添加副本：

```
hpa.yaml 
kind: HorizontalPodAutoscaler 
apiVersion: autoscaling/v2beta1 
metadata: 
  name: fib 
spec: 
  maxReplicas: 10 
  minReplicas: 1 
  scaleTargetRef: 
    apiVersion: app/v1 
    kind: Deployment 
    name: fib 
  metrics: 
  - type: Resource 
    resource: 
      name: cpu 
      targetAverageUtilization: 60 
```

使用`kubectl`创建自动缩放器：

```
kubectl apply -f hpa.yaml  
```

`kubectl autoscale`命令是创建`HorizontalPodAutoscaler`的快捷方式。运行`kubectl autoscale deployment fib --min=1 --max=10 --cpu-percent=60`将创建一个等效的自动缩放器。

创建了 Horizontal Pod Autoscaler 后，您可以使用`kubectl describe`查看有关其当前状态的许多有趣信息：

```
$ kubectl describe hpa fib    
Name:              fib
Namespace:         default
CreationTimestamp: Sat, 15 Sep 2018 14:32:46 +0100
Reference:         Deployment/fib
Metrics:           ( current / target )
  resource cpu:    0% (1m) / 60%
Min replicas:      1
Max replicas:      10
Deployment pods:   1 current / 1 desired  
```

现在我们已经设置好了 Horizontal Pod Autoscaler，我们应该在部署中的 Pod 上生成一些负载，以说明它的工作原理。在这种情况下，我们将使用`ab`（Apache benchmark）工具重复要求我们的应用程序计算第 30 个斐波那契数：

```
load.yaml
apiVersion: batch/v1 
kind: Job 
metadata: 
  name: fib-load 
  labels: 
    app: fib 
    component: load 
spec: 
  template: 
    spec: 
      containers: 
      - name: fib-load 
        image: errm/ab 
        args: ["-n1000", "-c4", "fib/30"] 
      restartPolicy: OnFailure 
```

此作业使用`ab`向端点发出 1,000 个请求（并发数为 4）。将作业提交到集群，然后观察水平 Pod 自动缩放器的状态：

```
kubectl apply -f load.yaml    
watch kubectl describe hpa fib
```

一旦负载作业开始发出请求，自动缩放器将扩展部署以处理负载：

```
Name:                   fib
Namespace:              default
CreationTimestamp: Sat, 15 Sep 2018 14:32:46 +0100
Reference:         Deployment/fib
Metrics:           ( current / target )
  resource cpu:    100% (251m) / 60%
Min replicas:      1
Max replicas:      10
Deployment pods:   2 current / 2 desired  
```

# 基于其他指标自动缩放 pod

度量服务器提供了水平 Pod 自动缩放器可以使用的 API，以获取有关集群中 pod 的 CPU 和内存利用率的信息。

可以针对利用率百分比进行目标设置，就像我们对 CPU 指标所做的那样，或者可以针对绝对值进行目标设置，就像我们对内存指标所做的那样：

```
hpa.yaml 
kind: HorizontalPodAutoscaler 
apiVersion: autoscaling/v2beta1 
metadata: 
  name: fib 
spec: 
  maxReplicas: 10 
  minReplicas: 1 
  scaleTargetRef: 
    apiVersion: app/v1 
    kind: Deployment 
    name: fib 
  metrics: 
  - type: Resource 
    resource: 
      name: memory 
      targetAverageValue: 20M 
```

水平 Pod 自动缩放器还允许我们根据更全面的指标系统提供的其他指标进行缩放。Kubernetes 允许聚合自定义和外部指标的指标 API。

自定义指标是与 pod 相关的除 CPU 和内存之外的指标。例如，您可以使用适配器，使您能够使用像 Prometheus 这样的系统从您的 pod 中收集的指标。

如果您有关于应用程序利用率的更详细的指标可用，这可能非常有益，例如，一个公开忙碌工作进程计数的分叉 Web 服务器，或者一个公开有关当前排队项目数量的指标的队列处理应用程序。

外部指标适配器提供有关与 Kubernetes 中的任何对象不相关的资源的信息，例如，如果您正在使用外部排队系统，比如 AWS SQS 服务。

总的来说，如果您的应用程序可以公开有关其所依赖的资源的指标，并使用外部指标适配器，那将更简单，因为很难限制对特定指标的访问，而自定义指标与特定的 Pod 相关联，因此 Kubernetes 可以限制只有那些需要使用它们的用户和进程才能访问它们。

# 集群自动缩放

Kubernetes Horizontal Pod Autoscaler 的功能使我们能够根据应用程序随时间变化的资源使用情况添加和删除 pod 副本。然而，这对我们集群的容量没有影响。如果我们的 pod 自动缩放器正在添加 pod 来处理负载增加，那么最终我们的集群可能会用尽空间，额外的 pod 将无法被调度。如果我们的应用程序负载减少，pod 自动缩放器删除 pod，那么我们就需要为 EC2 实例支付费用，而这些实例将处于空闲状态。

当我们在第七章中创建了我们的集群，*一个生产就绪的集群*，我们使用自动缩放组部署了集群节点，因此我们应该能够利用它根据部署到集群上的应用程序的需求随时间变化而扩展和收缩集群。

自动缩放组内置支持根据实例的平均 CPU 利用率来调整集群的大小。然而，当处理 Kubernetes 集群时，这并不是很合适，因为运行在集群每个节点上的工作负载可能会有很大不同，因此平均 CPU 利用率并不是集群空闲容量的很好代理。

值得庆幸的是，为了有效地将 pod 调度到节点上，Kubernetes 会跟踪每个节点的容量和每个 pod 请求的资源。通过利用这些信息，我们可以自动调整集群的大小以匹配工作负载的大小。

Kubernetes 自动缩放器项目为一些主要的云提供商提供了集群自动缩放器组件，包括 AWS。集群自动缩放器可以很简单地部署到我们的集群。除了能够向我们的集群添加实例外，集群自动缩放器还能够从集群中清除 pod，然后在集群容量可以减少时终止实例。

# 部署集群自动缩放器

将集群自动缩放器部署到我们的集群非常简单，因为它只需要一个简单的 pod 在运行。我们只需要一个简单的 Kubernetes 部署，就像我们在之前的章节中使用过的那样。

为了让集群自动缩放器更新自动缩放组的期望容量，我们需要通过 IAM 角色授予权限。如果您正在使用 kube2iam，正如我们在第七章中讨论的那样，我们将能够通过适当的注释为集群自动缩放器 pod 指定这个角色：

```
cluster_autoscaler.tf
data "aws_iam_policy_document" "eks_node_assume_role_policy" { 
  statement { 
    actions = ["sts:AssumeRole"] 
    principals { 
      type = "AWS" 
      identifiers = ["${aws_iam_role.node.arn}"] 
    } 
  } 
} 

resource "aws_iam_role" "cluster-autoscaler" { 
  name = "EKSClusterAutoscaler" 
  assume_role_policy = "${data.aws_iam_policy_document.eks_node_assume_role_policy.json}" 
} 

data "aws_iam_policy_document" "autoscaler" { 
  statement { 
    actions = [ 
      "autoscaling:DescribeAutoScalingGroups", 
      "autoscaling:DescribeAutoScalingInstances", 
      "autoscaling:DescribeTags", 
      "autoscaling:SetDesiredCapacity", 
      "autoscaling:TerminateInstanceInAutoScalingGroup" 
    ] 
    resources = ["*"] 
  } 
} 

resource "aws_iam_role_policy" "cluster_autoscaler" { 
  name = "cluster-autoscaler" 
  role = "${aws_iam_role.cluster_autoscaler.id}" 
  policy = "${data.aws_iam_policy_document.autoscaler.json}" 
} 
```

为了将集群自动缩放器部署到我们的集群，我们将使用`kubectl`提交一个部署清单，类似于我们在第七章中部署 kube2iam 的方式，*一个生产就绪的集群*。我们将使用 Terraform 的模板系统来生成清单。

我们创建一个服务账户，用于自动扩展器连接到 Kubernetes API：

```
cluster_autoscaler.tpl
--- 
apiVersion: v1 
kind: ServiceAccount 
metadata: 
  labels: 
    k8s-addon: cluster-autoscaler.addons.k8s.io 
    k8s-app: cluster-autoscaler 
  name: cluster-autoscaler 
  namespace: kube-system 
```

集群自动缩放器需要读取有关集群当前资源使用情况的信息，并且需要能够从需要从集群中移除并终止的节点中驱逐 Pod。基本上，`cluster-autoscalerClusterRole`为这些操作提供了所需的权限。以下是`cluster_autoscaler.tpl`的代码续写：

```
--- 
apiVersion: rbac.authorization.k8s.io/v1beta1 
kind: ClusterRole 
metadata: 
  name: cluster-autoscaler 
  labels: 
    k8s-addon: cluster-autoscaler.addons.k8s.io 
    k8s-app: cluster-autoscaler 
rules: 
- apiGroups: [""] 
  resources: ["events","endpoints"] 
  verbs: ["create", "patch"] 
- apiGroups: [""] 
  resources: ["pods/eviction"] 
  verbs: ["create"] 
- apiGroups: [""] 
  resources: ["pods/status"] 
  verbs: ["update"] 
- apiGroups: [""] 
  resources: ["endpoints"] 
  resourceNames: ["cluster-autoscaler"] 
  verbs: ["get","update"] 
- apiGroups: [""] 
  resources: ["nodes"] 
  verbs: ["watch","list","get","update"] 
- apiGroups: [""] 
  resources: ["pods","services","replicationcontrollers","persistentvolumeclaims","persistentvolumes"] 
  verbs: ["watch","list","get"] 
- apiGroups: ["extensions"] 
  resources: ["replicasets","daemonsets"] 
  verbs: ["watch","list","get"] 
- apiGroups: ["policy"] 
  resources: ["poddisruptionbudgets"] 
  verbs: ["watch","list"] 
- apiGroups: ["apps"] 
  resources: ["statefulsets"] 
  verbs: ["watch","list","get"] 
- apiGroups: ["storage.k8s.io"] 
  resources: ["storageclasses"] 
  verbs: ["watch","list","get"] 
--- 
apiVersion: rbac.authorization.k8s.io/v1beta1 
kind: ClusterRoleBinding 
metadata: 
  name: cluster-autoscaler 
  labels: 
    k8s-addon: cluster-autoscaler.addons.k8s.io 
    k8s-app: cluster-autoscaler 
roleRef: 
  apiGroup: rbac.authorization.k8s.io 
  kind: ClusterRole 
  name: cluster-autoscaler 
subjects: 
  - kind: ServiceAccount 
    name: cluster-autoscaler 
    namespace: kube-system 
```

请注意，`cluster-autoscaler`在配置映射中存储状态信息，因此需要有权限能够从中读取和写入。这个角色允许了这一点。以下是`cluster_autoscaler.tpl`的代码续写：

```
--- 
apiVersion: rbac.authorization.k8s.io/v1beta1 
kind: Role 
metadata: 
  name: cluster-autoscaler 
  namespace: kube-system 
  labels: 
    k8s-addon: cluster-autoscaler.addons.k8s.io 
    k8s-app: cluster-autoscaler 
rules: 
- apiGroups: [""] 
  resources: ["configmaps"] 
  verbs: ["create"] 
- apiGroups: [""] 
  resources: ["configmaps"] 
  resourceNames: ["cluster-autoscaler-status"] 
  verbs: ["delete","get","update"] 
--- 
apiVersion: rbac.authorization.k8s.io/v1beta1 
kind: RoleBinding 
metadata: 
  name: cluster-autoscaler 
  namespace: kube-system 
  labels: 
    k8s-addon: cluster-autoscaler.addons.k8s.io 
    k8s-app: cluster-autoscaler 
roleRef: 
  apiGroup: rbac.authorization.k8s.io 
  kind: Role 
  name: cluster-autoscaler 
subjects: 
  - kind: ServiceAccount 
    name: cluster-autoscaler 
    namespace: kube-system 
```

最后，让我们考虑一下集群自动缩放器部署本身的清单。集群自动缩放器 Pod 包含一个运行集群自动缩放器控制循环的单个容器。您会注意到我们正在向集群自动缩放器传递一些配置作为命令行参数。最重要的是，`--node-group-auto-discovery`标志允许自动缩放器在具有我们在第七章中创建集群时在我们的自动缩放组上设置的`kubernetes.io/cluster/<cluster_name>`标记的自动缩放组上操作。这很方便，因为我们不必显式地配置自动缩放器与我们的集群自动缩放组。

如果您的 Kubernetes 集群在多个可用区中有节点，并且正在运行依赖于被调度到特定区域的 Pod（例如，正在使用 EBS 卷的 Pod），建议为您计划使用的每个可用区创建一个自动缩放组。如果您使用跨多个区域的一个自动缩放组，那么集群自动缩放器将无法指定它启动的实例的可用区。

这是`cluster_autoscaler.tpl`的代码续写：

```
--- 
apiVersion: extensions/v1beta1 
kind: Deployment 
metadata: 
  name: cluster-autoscaler 
  namespace: kube-system 
  labels: 
    app: cluster-autoscaler 
spec: 
  replicas: 1 
  selector: 
    matchLabels: 
      app: cluster-autoscaler 
  template: 
    metadata: 
      annotations: 
        iam.amazonaws.com/role: ${iam_role} 
      labels: 
        app: cluster-autoscaler 
    spec: 
      serviceAccountName: cluster-autoscaler 
      containers: 
        - image: k8s.gcr.io/cluster-autoscaler:v1.3.3 
          name: cluster-autoscaler 
          resources: 
            limits: 
              cpu: 100m 
              memory: 300Mi 
            requests: 
              cpu: 100m 
              memory: 300Mi 
          command: 
            - ./cluster-autoscaler 
            - --v=4 
            - --stderrthreshold=info 
            - --cloud-provider=aws 
            - --skip-nodes-with-local-storage=false 
            - --expander=least-waste 
            - --node-group-auto-discovery=asg:tag=kubernetes.io/cluster/${cluster_name} 
          env: 
            - name: AWS_REGION 
              value: ${aws_region} 
          volumeMounts: 
            - name: ssl-certs 
              mountPath: /etc/ssl/certs/ca-certificates.crt 
              readOnly: true 
          imagePullPolicy: "Always" 
      volumes: 
        - name: ssl-certs 
          hostPath: 
            path: "/etc/ssl/certs/ca-certificates.crt" 
```

最后，我们通过传递 AWS 区域、集群名称和 IAM 角色的变量来渲染模板化的清单，并使用`kubectl`将文件提交给 Kubernetes：

这是`cluster_autoscaler.tpl`的代码续写：

```
data "aws_region" "current" {} 

data "template_file" " cluster_autoscaler " { 
  template = "${file("${path.module}/cluster_autoscaler.tpl")}" 

  vars { 
    aws_region = "${data.aws_region.current.name}" 
    cluster_name = "${aws_eks_cluster.control_plane.name}" 
    iam_role = "${aws_iam_role.cluster_autoscaler.name}" 
  } 
} 

resource "null_resource" "cluster_autoscaler" { 
  trigers = { 
    manifest_sha1 = "${sha1("${data.template_file.cluster_autoscaler.rendered}")}" 
  } 

  provisioner "local-exec" { 
    command = "kubectl  
--kubeconfig=${local_file.kubeconfig.filename} apply -f -<<EOF\n${data.template_file.cluster_autoscaler.rendered}\nEOF" 
  } 
} 
```

# 总结

Kubernetes 是一个强大的工具；它非常有效地实现了比手动将应用程序调度到机器上更高的计算资源利用率。重要的是，您要学会通过设置正确的资源限制和请求来为您的 Pod 分配资源；如果不这样做，您的应用程序可能会变得不可靠或者资源匮乏。

通过了解 Kubernetes 如何根据您分配给它们的资源请求和限制为您的 pod 分配服务质量类别，您可以精确控制您的 pod 的管理方式。通过确保您的关键应用程序（如 Web 服务器和数据库）以保证类别运行，您可以确保它们将始终表现一致，并在需要重新安排 pod 时遭受最小的中断。您可以通过为较低优先级的 pod 设置限制来提高集群的效率，这将导致它们以可突发的 QoS 类别进行安排。可突发的 pod 可以在有空闲资源时使用额外的资源，但在负载增加时不需要向集群添加额外的容量。

资源配额在管理大型集群时非常有价值，该集群用于运行多个应用程序，甚至由组织中的不同团队使用，特别是如果您试图控制非生产工作负载（如测试和分段环境）的成本。

AWS 之所以称其机器为弹性，是有原因的：它们可以在几分钟内按需扩展或缩减，以满足应用程序的需求。如果您在负载变化的集群上运行工作负载，那么您应该利用这些特性和 Kubernetes 提供的工具来扩展部署，以匹配应用程序接收的负载以及需要安排的 pod 的大小。


# 第九章：存储状态

本章主要介绍 Kubernetes 与 AWS 原生存储解决方案 Elastic Block Store（EBS）的深度集成。 Amazon EBS 提供网络附加存储作为服务，并且是提供块存储给 EC2 实例的主要解决方案。

几乎每个启动的 EC2 实例都由 EBS 根卷支持（从 AMI 机器映像创建）。由于 EBS 存储是网络附加的，如果支持 EC2 实例的底层机器以某种方式失败，存储在卷上的数据是安全的，因为它会自动在多个物理存储设备上复制。

除了用于存储 EC2 实例的根文件系统外，还可以通过 AWS API 将附加的 EBS 卷附加到 EC2 实例并按需挂载。 Kubernetes 与 AWS EBS 的集成利用了这一点，提供了可以被您的 pod 使用的持久卷。如果一个 pod 被杀死并被另一个 EC2 实例上的 pod 替换，Kubernetes 将处理将 EBS 卷从旧的 EC2 实例分离并附加到新实例，准备好根据需要挂载到新的 pod 中。

在本章中，我们将首先看看如何配置我们的 pod 以利用附加卷。然后，我们将研究 Kubernetes 提供的用于处理提供持久性的存储（如 EBS）的抽象。我们将看看 Kubernetes 如何根据我们在 pod 配置中请求的规格自动为我们提供 EBS 卷。

一旦您掌握了使用 Kubernetes 为您的 pod 提供持久存储，本章的下半部分将介绍有状态集，这是 Kubernetes 提供的一个抽象，用于运行一组 pod，每个 pod 都可以有自己的附加存储和即使重新调度到另一个节点也保持不变的身份。如果您想在 Kubernetes 集群上运行复杂的有状态应用程序，比如数据库，这是所需的最后一块拼图。

在本章中，我们将涵盖以下主题：

+   卷

+   存储类

+   有状态集

# 卷

让我们首先看一下如何将卷附加到我们的 Pod。可用的最简单的卷类型`emptyDir`只是一个与 Pod 的生命周期相关联的临时目录。当卷被创建时，它是空的，正如其名称所示，并且会一直保留在节点上，直到 Pod 从节点中移除。您在卷内存储的数据在同一节点上的 Pod 重启之间是持久的，因此可以用于需要在文件系统上缓存昂贵计算的进程，或者用于检查它们的进度。在第一章中，*Google 的基础设施供给我们*，我们讨论了`emptyDir`卷在 Pod 内不同容器之间共享文件的一些其他可能用途。

在这个例子中，我们将利用`emptyDir`卷来部署一个应用程序，该应用程序希望写入容器中的`/data`目录，而根文件系统已被设置为只读。

这个应用程序是为了说明 Kubernetes 中卷的一些属性而设计的。当它启动时，它会在`/data`目录中写入一个随机的文件名。然后它启动一个显示该目录内容的 Web 服务器：

```
apiVersion: apps/v1 
kind: Deployment 
metadata: 
  name: randserver 
spec: 
  selector: 
    matchLabels: 
      app: randserver 
  template: 
    metadata: 
      labels: 
        app: example 
    spec: 
      containers: 
      - image: errm/randserver 
        name: randserver 
        volumeMounts: 
        - mountPath: /data 
          name: data 
        securityContext: 
          readOnlyRootFilesystem: true 
      volumes: 
      - name: data 
        emptyDir: {} 
```

查看这个配置，有一些关于我们如何在 Pod 中使用卷的事项需要注意。这些规则不仅适用于`emptyDir`卷，也适用于您可能遇到的每一种卷类型：

+   每个卷都在 Pod 规范的顶层定义。即使一个卷被 Pod 中的多个容器使用，我们只需要定义一次。

+   当您想要从容器内访问卷时，您必须指定一个卷挂载点，将该卷挂载到容器的文件系统的特定位置。当我们挂载一个卷时，我们会用在`volumes`部分中定义它时使用的名称来引用它。

一旦您部署了这个示例清单，您应该能够使用`kubectl port-forward`命令来访问 Pod 内运行的 Web 服务器：

```
$ kubectl port-forward deployment/randserver 3000:3000   
Forwarding from 127.0.0.1:3000 -> 3000
Forwarding from [::1]:3000 -> 3000
```

现在您应该能够在浏览器中访问`http://localhost:3000`，以查看在容器启动时创建的一个随机文件：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-aws/img/2ec3e254-b8ec-41e1-a6c3-42b261d94d2f.png)

如果您删除此 Pod，那么部署将重新创建一个新的 Pod。因为`emptyDir`卷的内容在 Pod 被销毁时会丢失，所以当第一个 Pod 启动时创建的文件将会消失，并且将创建一个具有不同名称的新文件：

```
$ kubectl delete pod -l app=randserver
pod "randserver-79559c5fb6-htnxm" deleted  
```

您需要重新运行`kubectl port-forward`以选择新的 pod：

```
$ kubectl port-forward deployment/randserver 3000:3000  
```

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-aws/img/cda09f41-f300-412e-a001-43f1baa830a9.png)正在提供的新创建的文件

# EBS 卷

让 Kubernetes 附加 EBS 卷，然后将其挂载到我们的 pod 中的容器中，几乎与使用`emptyDir`卷一样简单。挂载 EBS 卷的最低级别和最简单的方法是使用`awsElasticBlockStore`卷类型。此卷类型处理将 EBS 卷附加到我们的 pod 将运行的节点，然后将卷挂载到容器中的路径。

在使用此卷类型时，Kubernetes 不处理实际为我们创建卷，因此我们需要手动执行此操作。我们可以使用 AWS CLI 来执行此操作：

```
$ aws ec2 create-volume --availability-zone=us-east-1a --size=5 --volume-type=gp2
{
 "AvailabilityZone": "us-east-1a",
 "CreateTime": "2018-11-17T15:17:54.000Z",
 "Encrypted": false,
 "Size": 5,
 "SnapshotId": "",
 "State": "creating",
 "VolumeId": "vol-04e744aad50d4911",
 "Iops": 100,
 "Tags": [],
 "VolumeType": "gp2"
} 
```

请记住，EBS 卷与特定的可用性区域（就像`ec2`实例一样）相关联，并且只能附加到该相同可用性区域中的实例，因此您需要在与集群中的实例相同的区域中创建卷。

在这里，我们已更新了上一个示例中创建的部署，以使用`awsElasticBlockStore`卷类型，并将我们刚刚创建的卷附加到我们的 pod。EBS 卷的 ID 作为参数传递给卷配置：

```
apiVersion: apps/v1 
kind: Deployment 
metadata: 
  name: randserver 
spec: 
  selector: 
    matchLabels: 
      app: randserver 
  template: 
    metadata: 
      labels: 
        app: randserver 
    spec: 
      containers: 
      - image: errm/randserver 
        name: randserver 
        volumeMounts: 
        - mountPath: /data 
          name: data 
        securityContext: 
          readOnlyRootFilesystem: true 
      volumes: 
      - name: data 
        awsElasticBlockStore: 
          volumeID: vol-04e744aad50d4911 
          fsType: ext4 
      nodeSelector: 
        "failure-domain.beta.kubernetes.io/zone": us-east-1a 
```

您将看到以这种方式手动附加 EBS 卷与使用更简单的`emptyDir`卷非常相似。

特殊的`failure-domain.beta.kubernetes.io/zone`标签由 AWS 云提供商自动添加到每个节点。在这里，我们在 pod 定义的`nodeSelector`中使用它，以将 pod 调度到与我们在其中创建卷的可用性区域相同的节点。Kubernetes 将自动向您的集群中的节点添加几个其他标签。您可以在 Kubernetes 文档中阅读有关它们的信息[`kubernetes.io/docs/reference/kubernetes-api/labels-annotations-taints/`](https://kubernetes.io/docs/reference/kubernetes-api/labels-annotations-taints/)。

当您首次提交此部署时，其行为将与先前版本完全相同。但是，当我们删除该 pod 并进行替换时，您会注意到在此容器的先前运行中创建的文件将保留，并且每次启动时都会向列表中添加一个新文件：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-aws/img/dee678a3-6597-4cd5-ac44-c64a26143d86.png)当我们的应用程序由 EBS 卷支持时，文件将在 pod 重新调度时保留

# 持久卷

虽然我们当然可以以这种方式手动创建 EBS 卷并在我们的清单中使用它们的 ID，但这种方法存在一些问题。

对于想要在集群上运行他们的应用程序的用户来说，首先考虑为应用程序提供 EBS 卷，然后再修改清单以引用硬编码的 ID，这是笨拙且耗时的。这意味着 pod 清单将需要包含特定于在 AWS 上运行所涉及的应用程序的配置。理想情况下，我们希望尽可能多地重用我们的配置，以避免由于不得不修改配置而引入错误的风险，这些配置可能在我们可能部署它的不同环境之间重复使用。

Kubernetes 提供了两个抽象，将帮助我们管理 EBS 卷：`PersistentVolume`和`PersistentVolumeClaim`。

`PersistentVolume`对象代表集群中的物理存储空间；在 AWS 上，这是一个 EBS 卷，就像`Node`对象代表集群中的 EC2 实例一样。该对象捕获了存储实现的细节，因此对于 EBS 卷，它记录了其 ID，以便 Kubernetes 在调度使用该卷的 pod 时将其附加到正确的节点上。

`PersistentVolumeClaim`是 Kubernetes 对象，允许我们在 pod 中表达对`PersistentVolume`的请求。当我们请求持久卷时，我们只需要请求所需的存储量，以及可选的存储类（请参见下一节）。`PersistentVolumeClaim`通常嵌入在 pod 规范中。当 pod 被调度时，它的`PersistentVolumeClaim`将与足够大以满足所请求存储量的特定`PersistentVolume`匹配。`PersistentVolume`绑定到请求的`PersistentVolumeClaim`，因此即使 pod 被重新调度，相同的基础卷也将附加到 pod 上。

这比手动提供 EBS 卷并在我们的配置中包含卷 ID 要大大改进，因为我们不需要在每次将我们的 pod 部署到新环境时修改我们的清单。

如果你手动操作 Kubernetes（例如，在裸金属部署中），集群管理员可能会预先提供一组`PersistentVolume`，然后在创建时与每个`PersistentVolumeClaim`匹配并绑定。在使用 AWS 时，无需预先提供存储，因为 Kubernetes 会根据需要使用 AWS API 动态创建`PersistentVolume`。

# 持久卷示例

让我们看看如何使用持久卷来简化我们示例应用程序的部署。

为了避免在 AWS 账户上产生额外的费用，你可能想要删除在上一个示例中手动创建的 EBS 卷。

首先，删除我们创建的部署，这样 Kubernetes 就可以卸载卷：

`**$ kubectl delete deployment/randserver**`然后，你可以使用 AWS CLI 来删除 EBS 卷：

`**$ aws ec2 delete-volume --volume-id vol-04e744aad50d4911**`

在开始之前，请确保您至少已将通用存储类添加到您的集群中。

使用 Kubernetes 动态卷提供创建 EBS 卷就像使用`kubectl`创建任何其他资源一样简单：

```
apiVersion: v1 
kind: PersistentVolumeClaim 
metadata: 
  name: randserver-data 
spec: 
  accessModes: 
    - ReadWriteOnce 
  storageClassName: general-purpose 
  resources: 
    requests: 
      storage: 1Gi 
```

如果你在集群中的存储类中添加了`storageclass.kubernetes.io/is-default-class`注释，如果你愿意，你可以省略`storageClassName`字段。

一旦你使用`kubernetes.io/aws-ebs`供应商为存储类创建了`PersistantVolumeClaim`，Kubernetes 将会根据你指定的大小和存储类参数来提供一个匹配的 EBS 卷。完成后，你可以使用`kubectl describe`来查看声明；你会看到状态已更新为`Bound`，`Volume`字段显示了声明绑定的底层`PersistentVolume`：

```
$ kubectl describe pvc/randserver-data
Name:          randserver-data
Namespace:     default
StorageClass:  general-purpose
Status:        Bound
Volume:        pvc-5c2dab0d-f017-11e8-92ac-0a56f9f52542
Capacity:      1Gi
Access Modes:  RWO

```

如果我们使用`kubectl describe`来检查这个`PersistentVolume`，我们可以看到自动提供的底层 EBS 卷的细节：

```
$ kubectl describe pv/pvc-5c2dab0d-f017-11e8-92ac-0a56f9f52542
Name: pvc-5c2dab0d-f017-11e8-92ac-0a56f9f52542
StorageClass: general-purpose
Status: Bound
Claim: default/randserver-data
Reclaim Policy: Delete
Access Modes: RWO
Capacity: 1Gi
Source:
 Type: AWSElasticBlockStore (a Persistent Disk resource in AWS)
 VolumeID: aws://us-east-1a/vol-04ad625aa4d5da62b
 FSType: ext4
 Partition: 0
 ReadOnly: false
```

在我们的部署中，我们可以更新 pod 规范的`volumes`部分，通过名称引用`PersistentVolumeClaim`：

```
apiVersion: apps/v1 
kind: Deployment 
metadata: 
  name: randserver 
spec: 
  selector: 
    matchLabels: 
      app: randserver 
  template: 
    metadata: 
      labels: 
        app: randserver 
    spec: 
      containers: 
      - image: errm/randserver 
        name: randserver 
        volumeMounts: 
        - mountPath: /data 
          name: data 
        securityContext: 
          readOnlyRootFilesystem: true 
      volumes: 
      - name: data 
        persistentVolumeClaim: 
          claimName: randserver-data 
```

# 存储类

在 AWS 上，有几种不同类型的卷可用，提供不同的价格和性能特性。

为了在我们提供卷时提供一种简单的选择卷类型（和其他一些设置），我们创建了一个`StorageClass`对象，然后在创建`PersistentVolumeClaim`时可以通过名称引用它。

存储类的创建方式与任何其他 Kubernetes 对象相同，通过使用`kubectl`向 API 提交清单来创建：

```
kind: StorageClass 
apiVersion: storage.k8s.io/v1 
metadata: 
  name: general-purpose 
  annotations: 
    "storageclass.kubernetes.io/is-default-class": "true" 
provisioner: kubernetes.io/aws-ebs 
parameters: 
  type: gp2 
```

此清单创建了一个名为`general-purpose`的存储类，该存储类创建具有`gp2`卷类型的卷。如果您还记得我们在第六章中关于 EBS 卷类型的讨论，*生产规划*，这种基于 SSD 的卷类型适用于大多数通用应用程序，提供了良好的性能和价格平衡。

您还会注意到`storageclass.kubernetes.io/is-default-class`注释，该注释使`StorageClass`成为任何未指定存储类的`PersistentVolumeClaim`要使用的默认存储类。您应该只将此注释应用于单个`StorageClass`。

`parameter`字段接受几种不同的选项。

最重要的参数字段是`type`，它允许我们选择`gp2`（默认值）、`io1`（预留 IOPS）、`sc1`（冷存储）或`st1`（吞吐量优化）中的一个。

如果您选择使用`io1`类型，还应使用`iopsPerGB`参数来指定每 GB 磁盘存储请求的 IOPS 数量。`io1` EBS 卷支持的最大 IOPS/GB 比率为 50:1。

请记住，预留 IOPS 的成本使`io1`卷的成本比等效的通用卷高得多。为了提供与相同大小的`gp2`卷相似的吞吐量，预留 IOPS 的`io1`卷的成本可能是后者的三倍。因此，您应该仅在需要超过`gp2`卷提供的性能时才使用`io1`卷。一个可以优化成本的技巧是使用比应用程序要求的更大的`gp2`卷，以提供额外的 IO 积分。

例如，您可以创建几个不同的使用`io1`类型的类，供具有不同性能要求的应用程序使用：

```
kind: StorageClass 
apiVersion: storage.k8s.io/v1 
metadata: 
  name: high-iops-ssd 
provisioner: kubernetes.io/aws-ebs 
parameters: 
  type: io1 
  iopsPerGB: "50" 
---
 kind: StorageClass 
apiVersion: storage.k8s.io/v1 
metadata: 
  name: medium-iops-ssd 
provisioner: kubernetes.io/aws-ebs 
parameters: 
  type: io1 
  iopsPerGB: "25" 
```

请注意，Kubernetes 期望为`iopsPerGb`字段提供字符串值，因此您需要引用此值。

如果您使用的应用程序经过优化，可以对文件系统进行顺序读写操作，那么您可能会从使用`st1`卷类型中受益，该类型使用优化的磁盘存储提供高吞吐量的读写。不建议将此存储用于通用用途，因为进行随机访问读取或写入时的性能将很差：

```
kind: StorageClass 
apiVersion: storage.k8s.io/v1 
metadata: 
  name: throughput 
provisioner: kubernetes.io/aws-ebs 
parameters: 
  type: st1 
```

`sc1` 卷类型提供了作为 EBS 卷可用的最低成本存储，并且适用于不经常访问的数据。与 `st1` 卷一样，`sc1` 优化了顺序读写，因此在具有随机读写的工作负载上性能较差。

```
kind: StorageClass 
apiVersion: storage.k8s.io/v1 
metadata: 
  name: cold-storage 
provisioner: kubernetes.io/aws-ebs 
parameters: 
  type: sc1 
```

提前决定您想在集群中提供的不同存储类，并向集群用户提供关于何时使用每个类的文档是一个好主意。

在您的配置过程中，考虑提交一个存储类列表到您的集群中，因为在配置 EKS 集群时，默认情况下不会创建任何存储类。

# 有状态集

到目前为止，我们已经看到了如何使用 Kubernetes 自动为 `PersistentVolumeClaim` 配置 EBS 卷。这对于许多需要单个卷为单个 pod 提供持久性的应用程序非常有用。

然而，当我们尝试扩展我们的部署时，我们会遇到问题。运行在同一节点上的 pod 可能最终共享卷。但是，由于 EBS 卷一次只能附加到单个实例，任何调度到另一个节点的 pod 都将被卡在 `ContainerCreating` 状态，无休止地等待 EBS 卷被附加。

如果您正在运行一个应用程序，希望每个副本都有自己独特的卷，我们可以使用有状态集。当我们想要部署每个副本都需要有自己的持久存储的应用程序时，有状态集比部署具有两个关键优势。

首先，我们可以提供一个模板来为每个 pod 创建一个新的持久卷，而不是通过名称引用单个持久卷。这使我们能够通过扩展有状态集为每个 pod 副本提供独立的 EBS 卷。如果我们想要通过部署实现这一点，我们需要为每个副本创建一个单独的部署，每个部署通过名称引用不同的持久卷。

其次，当通过 `StatefulSet` 调度 pod 时，每个副本都有一个一致和持久的主机名，即使 pod 被重新调度到另一个节点，主机名也保持不变。这在运行软件时非常有用，每个副本都希望能够连接到特定地址的同行。在 Kubernetes 添加有状态集之前，将这样的软件部署到 Kubernetes 通常依赖于使用 Kubernetes API 执行服务发现的特殊插件。

为了说明有状态集的工作原理，我们将重写我们的示例应用部署清单，以使用`StatefulSet`。因为`StatefulSet`中的每个副本 Pod 都有可预测的主机名，所以我们首先需要创建一个服务，以允许将流量路由到这些主机名并传递到底层的 Pod：

```
apiVersion: v1 
kind: Service 
metadata: 
  name: randserver 
  labels: 
    app: randserver 
spec: 
  ports: 
  - port: 80 
    name: web 
    targetPort: 3000 
  clusterIP: None 
  selector: 
    app: randserver 
```

每个 Pod 将被赋予一个由有状态集的名称和集合中的 Pod 编号构成的主机名。主机名的域是服务的名称。

因此，当我们创建一个名为`randserver`的有三个副本的有状态集。集合中的 Pod 将被赋予主机名`randserver-0`，`randserver-1`和`randserver-2`。集群中运行的其他服务将能够通过使用名称`randserver-0.randserver`，`randserver-1.randserver`和`randserver-2.randserver`连接到这些 Pod。

`StatefulSet`的配置与部署的配置非常相似。应该注意的主要区别如下：

+   `serviceName`字段是我们需要引用用于为 Pod 提供网络访问的服务。

+   `volumeClaimTemplates`字段，我们在其中包含一个`PersistentVolumeClaim`的模板，该模板将为`StatefulSet`中的每个 Pod 副本创建。您可以将其视为为每个创建的 Pod 提供模板的模板字段的类比：

```
apiVersion: apps/v1 
kind: StatefulSet 
metadata: 
  name: randserver 
spec: 
  selector: 
    matchLabels: 
      app: randserver 
  serviceName: randserver 
  replicas: 3 
  template: 
    metadata: 
      labels: 
        app: randserver 
    spec: 
      containers: 
      - image: errm/randserver 
        name: randserver 
        volumeMounts: 
        - mountPath: /data 
          name: data 
        securityContext: 
          readOnlyRootFilesystem: true 
  volumeClaimTemplates: 
    - metadata: 
        name: data 
      spec: 
        accessModes: 
          - ReadWriteOnce 
        storageClassName: general-purpose 
        resources: 
          requests: 
            storage: 1Gi 
```

一旦您将`StatefulSet`提交给 Kubernetes，您应该能够看到已成功调度到集群的 Pod：

```
$ kubectl get pods
NAME           READY     STATUS    RESTARTS   AGE
randserver-0   1/1       Running   0          39s
randserver-1   1/1       Running   0          21s
randserver-2   1/1       Running   0          10s  
```

请注意，每个 Pod 的名称都遵循可预测的模式，不像使用部署或副本集创建的 Pod，它们每个都有一个随机名称。

尝试删除有状态集中的一个 Pod，并注意它被一个与被删除的 Pod 完全相同的名称的 Pod 所替换：

```
$ kubectl delete pod/randserver-1
$ kubectl get pods
NAME           READY     STATUS    RESTARTS   AGE
randserver-0   1/1       Running   0          17m
randserver-1   1/1       Running   0          18s
randserver-2   1/1       Running   0          17m  
```

如果您查看持久卷索赔，您将看到它们的名称也遵循可预测的模式，索赔的名称是由卷索赔模板元数据中给定的名称，有状态集的名称和 Pod 编号组成的。

```
kubectl get pvc
NAME                STATUS    VOLUME
data-randserver-0   Bound     pvc-803210cf-f027-11e8-b16d
data-randserver-1   Bound     pvc-99192c41-f027-11e8-b16d
data-randserver-2   Bound     pvc-ab2b25b1-f027-11e8-b16d  
```

如果删除（或缩减）一个有状态集，那么相关的持久卷索赔将保留。这非常有利，因为它使得更难丢失应用程序创建的宝贵数据。如果稍后重新创建（或扩展）有状态集，那么由于使用可预测的名称，相同的卷将被重用。

如果您确实打算从集群中完全删除有状态集，您可能还需要另外删除相应的持久卷声明：

```
$ kubectl delete statefulset randserver
statefulset.apps "randserver" deleted
$ kubectl delete pvc -l app=randserver
persistentvolumeclaim "data-randserver-0" deleted
persistentvolumeclaim "data-randserver-1" deleted
persistentvolumeclaim "data-randserver-2" deleted  
```

# 摘要

在本章中，我们已经了解了 Kubernetes 为您的应用程序提供存储的丰富工具集。

您应该已经学会了以下内容：

+   如何为您的 pod 配置卷

+   如何将卷挂载到容器中

+   如何使用持久卷声明自动提供 EBS 卷

+   通过配置存储类来提供不同的 EBS 卷类型

+   如何为有状态集中的每个 pod 动态提供卷

现在您应该已经掌握足够的知识，可以将许多类型的应用程序部署到您的 Kubernetes 集群中。

# 进一步阅读

如果您想了解如何在 Kubernetes 中利用存储，这里有一些资源可能对您有用：

+   Kubernetes Helm Charts 包括许多配置示例，用于众所周知的数据存储，这些示例广泛使用持久卷：[`github.com/helm/charts`](https://github.com/helm/charts)

+   Kubernetes 文档详细介绍了在 Kubernetes 中使用存储的信息：[`kubernetes.io/docs/concepts/storage/`](https://kubernetes.io/docs/concepts/storage/)

+   Kubernetes EFS 供应程序提供了一个附加的供应程序，可以部署以提供由 AWS 弹性文件系统（EFS）支持的卷。如果您希望多个 pod 能够从同一卷中读取和写入，这可能是一个有用的工具：[`github.com/kubernetes-incubator/external-storage/tree/master/aws/efs`](https://github.com/kubernetes-incubator/external-storage/tree/master/aws/efs)


# 第十章：管理容器映像

容器编排平台需要一个坚实的基础来运行我们的容器。基础设施的一个重要组成部分是存储容器映像的位置，这将允许我们在创建 pod 时可靠地获取它们。

从开发人员的角度来看，应该非常容易和快速地推送新的映像，同时开发我们希望部署到 Kubernetes 的软件。我们还希望有机制帮助我们进行版本控制、编目和描述如何使用我们的图像，以便促进部署并减少交付错误版本或配置的风险。

容器映像通常包含知识产权、专有源代码、基础设施配置秘密，甚至商业机密。因此，我们需要适当的身份验证和授权机制来保护它们免受未经授权的访问。

在本章中，我们将学习如何利用 AWS 弹性容器注册表（ECR）服务来存储我们的容器映像，以满足所有这些需求。

在本章中，我们将涵盖以下主题：

+   将 Docker 映像推送到 ECR

+   给图像打标签

+   给图像打标签

# 将 Docker 映像推送到 ECR

目前，存储和传递 Docker 映像的最常见方式是通过 Docker 注册表，这是 Docker 的一个开源应用程序，用于托管 Docker 仓库。这个应用程序可以部署在本地，也可以作为多个提供商的服务使用，比如 Docker Hub、Quay.io 和 AWS ECR。

该应用程序是一个简单的无状态服务，其中大部分维护工作涉及确保存储可用、安全和安全。正如任何经验丰富的系统管理员所知道的那样，这绝非易事，特别是如果有一个大型数据存储。因此，特别是如果您刚开始，强烈建议使用托管解决方案，让其他人负责保持图像的安全和可靠可用。

ECR 是 AWS 对托管 Docker 注册表的方法，每个帐户有一个注册表，使用 AWS IAM 对用户进行身份验证和授权以推送和拉取图像。默认情况下，仓库和图像的限制都设置为 1,000。正如我们将看到的，设置流程感觉非常类似于其他 AWS 服务，同时也对 Docker 注册表用户来说是熟悉的。

# 创建一个仓库

要创建一个仓库，只需执行以下`aws ecr`命令即可：

```
$ aws ecr create-repository --repository-name randserver 
```

这将创建一个存储我们`randserver`应用程序的存储库。其输出应该如下所示：

```
 {
 "repository": {
 "repositoryArn": "arn:aws:ecr:eu-central-1:123456789012:repository/randserver",
 "registryId": "123456789012",
 "repositoryName": "randserver",
 "repositoryUri": "123456789012.dkr.ecr.eu-central-1.amazonaws.com/randserver",
 "createdAt": 1543162198.0
 }
 } 
```

对您的存储库的一个不错的补充是一个生命周期策略，清理旧版本的图像，这样您最终不会被阻止推送更新版本。可以通过使用相同的`aws ecr`命令来实现：

```
$ aws ecr put-lifecycle-policy --registry-id 123456789012 --repository-name randserver --lifecycle-policy-text '{"rules":[{"rulePriority":10,"description":"Expire old images","selection":{"tagStatus":"any","countType":"imageCountMoreThan","countNumber":800},"action":{"type":"expire"}}]}'  
```

一旦在同一个存储库中有超过 800 个图像，这个特定的策略将开始清理。您还可以根据图像、年龄或两者进行清理，以及仅考虑清理中的一些标签。

有关更多信息和示例，请参阅[`docs.aws.amazon.com/AmazonECR/latest/userguide/lifecycle_policy_examples.html`](https://docs.aws.amazon.com/AmazonECR/latest/userguide/lifecycle_policy_examples.html)。

# 从您的工作站推送和拉取图像

为了使用您新创建的 ECR 存储库，首先我们需要对本地 Docker 守护程序进行身份验证，以针对 ECR 注册表。再次，`aws ecr`将帮助您实现这一点：

```
aws ecr get-login --registry-ids 123456789012 --no-include-email  
```

这将输出一个`docker login`命令，该命令将为您的 Docker 配置添加一个新的用户密码对。您可以复制粘贴该命令，或者您可以按照以下方式运行它；结果将是一样的：

```
$(aws ecr get-login --registry-ids 123456789012 --no-include-email)  
```

现在，推送和拉取图像就像使用任何其他 Docker 注册表一样，使用创建存储库时得到的存储库 URI 输出：

```
$ docker push 123456789012.dkr.ecr.eu-central-1.amazonaws.com/randserver:0.0.1    
$ docker pull 123456789012.dkr.ecr.eu-central-1.amazonaws.com/randserver:0.0.1  
```

# 设置推送图像的权限

IAM 用户的权限应该允许您的用户执行严格需要的操作，以避免可能会产生更大影响的任何可能的错误。对于 ECR 管理也是如此，为此，有三个 AWS IAM 托管策略大大简化了实现它的过程：

+   `AmazonEC2ContainerRegistryFullAccess`：这允许用户对您的 ECR 存储库执行任何操作，包括删除它们，因此应该留给系统管理员和所有者。

+   `AmazonEC2ContainerRegistryPowerUser`：这允许用户在任何存储库上推送和拉取图像，对于正在积极构建和部署您的软件的开发人员非常方便。

+   `AmazonEC2ContainerRegistryReadOnly`：这允许用户在任何存储库上拉取图像，对于开发人员不是从他们的工作站推送软件，而是只是拉取内部依赖项来处理他们的项目的情况非常有用。

所有这些策略都可以附加到 IAM 用户，方法是通过将 ARN 末尾的策略名称替换为适当的策略（如前所述），并将`--user-name`指向您正在管理的用户：

```
$ aws iam attach-user-policy --policy-arn arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly  --user-name johndoe
```

所有这些由 AWS 管理的策略都具有一个重要特征-它们都为您的注册表上的所有存储库添加权限。您可能会发现有几种情况远非理想-也许您的组织有几个团队不需要访问彼此的存储库；也许您希望有一个有权删除一些存储库但不是全部的用户；或者您只需要对**持续集成**（**CI**）设置中的单个存储库进行访问。

如果您的需求符合上述描述的任何情况，您应该创建自己的策略，并具有所需的细粒度权限。

首先，我们将为我们的`randserver`应用程序的开发人员创建一个 IAM 组：

```
$ aws iam create-group --group-name randserver-developers
    {
          "Group": {
          "Path": "/",
          "GroupName": "randserver-developers",
          "GroupId": "AGPAJRDMVLGOJF3ARET5K",
          "Arn": "arn:aws:iam::123456789012:group/randserver-developers",
          "CreateDate": "2018-10-25T11:45:42Z"
          }
    } 
```

然后我们将`johndoe`用户添加到组中：

```
$ aws iam add-user-to-group --group-name randserver-developers --user-name johndoe  
```

现在我们需要创建我们的策略，以便我们可以将其附加到组上。将此 JSON 文档复制到文件中：

```
{ 
   "Version": "2012-10-17", 
   "Statement": [{ 
         "Effect": "Allow", 
         "Action": [ 
               "ecr:GetAuthorizationToken", 
               "ecr:BatchCheckLayerAvailability", 
               "ecr:GetDownloadUrlForLayer", 
               "ecr:GetRepositoryPolicy", 
               "ecr:DescribeRepositories", 
               "ecr:ListImages", 
               "ecr:DescribeImages", 
               "ecr:BatchGetImage", 
               "ecr:InitiateLayerUpload", 
               "ecr:UploadLayerPart", 
               "ecr:CompleteLayerUpload", 
               "ecr:PutImage"
          ], 
         "Resource": "arn:aws:ecr:eu-central-1:123456789012:repository/randserver" 
   }] 
} 
```

要创建策略，请执行以下操作，传递适当的 JSON 文档文件路径：

```
$ aws iam create-policy --policy-name EcrPushPullRandserverDevelopers --policy-document file://./policy.json

    {
          "Policy": {
          "PolicyName": "EcrPushPullRandserverDevelopers",
          "PolicyId": "ANPAITNBFTFWZMI4WFOY6",
          "Arn": "arn:aws:iam::123456789012:policy/EcrPushPullRandserverDevelopers",
          "Path": "/",
          "DefaultVersionId": "v1",
          "AttachmentCount": 0,
          "PermissionsBoundaryUsageCount": 0,
          "IsAttachable": true,
          "CreateDate": "2018-10-25T12:00:15Z",
          "UpdateDate": "2018-10-25T12:00:15Z"
          }
    }  
```

最后一步是将策略附加到组，以便`johndoe`和这个应用程序的所有未来开发人员可以像我们之前一样从他们的工作站使用存储库：

```
$ aws iam attach-group-policy --group-name randserver-developers --policy-arn arn:aws:iam::123456789012:policy/EcrPushPullRandserverDevelopers 
```

# 在 Kubernetes 中使用存储在 ECR 上的图像

您可能还记得，在第七章中，*生产就绪的集群*，我们将 IAM 策略`AmazonEC2ContainerRegistryReadOnly`附加到了我们集群节点使用的实例配置文件。这允许我们的节点在托管集群的 AWS 帐户中的任何存储库中获取任何图像。

为了以这种方式使用 ECR 存储库，您应该将清单上的 pod 模板的`image`字段设置为指向它，就像以下示例中一样：

```
image: 123456789012.dkr.ecr.eu-central-1.amazonaws.com/randserver:0.0.1.
```

# 给图像打标签

每当将 Docker 图像推送到注册表时，我们需要使用标签标识图像。标签可以是任何字母数字字符串：`latest stable v1.7.3`甚至`c31b1656da70a0b0b683b060187b889c4fd1d958`都是您可能用来标识推送到 ECR 的图像的完全有效的示例标签。

根据软件的开发和版本控制方式，您在此标签中放入的内容可能会有所不同。根据不同类型的应用程序和开发流程，可能会采用三种主要策略来生成图像。

# 版本控制系统（VCS）引用

当您从源代码受版本控制系统管理的软件构建图像时，例如 Git，此时标记图像的最简单方式是利用来自您 VCS 的提交 ID（在使用 Git 时通常称为 SHA）。这为您提供了一个非常简单的方式来确切地检查您的代码当前正在运行的版本。

这种策略通常适用于以增量方式交付小改动的应用程序。您的图像的新版本可能会每天推送多次，并自动部署到测试和类生产环境中。这些应用程序的良好示例是 Web 应用程序和其他以服务方式交付的软件。

通过将提交 ID 通过自动化测试和发布流水线，您可以轻松生成软件确切修订版本的部署清单。

# 语义版本

然而，如果您正在构建用于许多用户使用的容器图像，无论是您组织内的多个用户，还是当您公开发布图像供第三方使用时，这种策略会变得更加繁琐和难以处理。对于这类应用程序，使用具有一定含义的语义版本号可能会有所帮助，帮助依赖于您图像的人决定是否安全地迁移到新版本。

这些图像的常见方案称为**语义化版本**（**SemVer**）。这是由三个由点分隔的单独数字组成的版本号。这些数字被称为**MAJOR**、**MINOR**和**PATCH**版本。语义版本号以`MAJOR.MINOR.PATCH`的形式列出这些数字。当一个数字递增时，右边的不那么重要的数字将被重置为`0`。

这些版本号为下游用户提供了有关新版本可能如何影响兼容性的有用信息：

+   每当实施了一个保持向后兼容的错误修复或安全修复时，`PATCH`版本会递增

+   每当添加一个保持向后兼容的新功能时，`MINOR`版本号会递增

+   任何破坏向后兼容性的更改都应该增加 `MAJOR` 版本号

这很有用，因为镜像的用户知道 `MINOR` 或 `PATCH` 级别的更改不太可能导致任何问题，因此升级到新版本时只需要进行基本测试。但是，如果升级到新的 `MAJOR` 版本，他们应该检查和测试更改的影响，这可能需要更改配置或集成代码。

您可以在 [`semver.org/`](https://semver.org/) 了解更多关于 SemVer 的信息。

# 上游版本号

通常，当我们构建重新打包现有软件的容器镜像时，希望使用打包软件本身的原始版本号。有时，为了对打包软件使用的配置进行版本控制，添加后缀可能会有所帮助。

在较大的组织中，常常会将软件工具与组织特定的默认配置文件打包在一起。您可能会发现将配置文件与软件工具一起进行版本控制很有用。

如果我要为我的组织打包 MySQL 数据库供使用，镜像标签可能看起来像 `8.0.12-c15`，其中 `8.0.12` 是上游 MySQL 版本，`c15` 是我为包含在我的容器镜像中的 MySQL 配置文件创建的版本号。

# 给镜像贴标签

如果您的软件开发和发布流程稍微复杂，您可能会迅速发现自己希望在镜像标签中添加更多关于镜像的语义信息，而不仅仅是简单的版本号。这可能很快变得难以管理，因为每当您想添加一些额外信息时，都需要修改构建和部署工具。

感谢地，Docker 镜像携带标签，可用于存储与镜像相关的任何元数据。

在构建时，可以使用 Dockerfile 中的 `LABEL` 指令为镜像添加标签。`LABEL` 指令接受多个键值对，格式如下：

```
LABEL <key>=<value> <key>=<value> ... 
```

使用此指令，我们可以在镜像上存储任何我们认为有用的任意元数据。由于元数据存储在镜像内部，不像标签那样可以更改。通过使用适当的镜像标签，我们可以发现来自我们版本控制系统的确切修订版，即使镜像已被赋予不透明的标签，如 `latest` 或 `stable`。

如果要在构建时动态设置这些标签，还可以在 Dockerfile 中使用 `ARG` 指令。

让我们看一个使用构建参数设置标签的例子。这是一个示例 Dockerfile：

```
FROM scratch 
ARG SHA  
ARG BEAR=Paddington 
LABEL git-commit=$GIT_COMMIT \ 
      favorite-bear=$BEAR \ 
      marmalade="5 jars" 
```

当我们构建容器时，我们可以使用`--build-arg`标志传递标签的值。当我们想要传递动态值，比如 Git 提交引用时，这是很有用的：

```
docker build --build-arg SHA=`git rev-parse --short HEAD` -t bear . 
```

与 Kubernetes 允许您附加到集群中对象的标签一样，您可以自由地使用任何方案为您的图像添加标签，并保存对您的组织有意义的任何元数据。

开放容器倡议（OCI），一个促进容器运行时和其图像格式标准的组织，已经提出了一套标准标签，可以用来提供有用的元数据，然后可以被其他理解它们的工具使用。如果您决定向您的容器图像添加标签，选择使用这套标签的部分或全部可能是一个很好的起点。

这些标签都以`org.opencontainers.image`为前缀，以便它们不会与您可能已经使用的任何临时标签发生冲突：

+   `* org.opencontainers.image.title`：这应该是图像的可读标题。例如，`Redis`。

+   `org.opencontainers.image.description`：这应该是图像的可读描述。例如，`Redis 是一个开源的键值存储`。

+   `org.opencontainers.image.created`：这应该包含图像创建的日期和时间。它应该按照 RFC 3339 格式。例如，`2018-11-25T22:14:00Z`。

+   `org.opencontainers.image.authors`：这应该包含有关负责此图像的人或组织的联系信息。通常，这可能是电子邮件地址或其他相关联系信息。例如，`Edward Robinson <ed@errm.co.uk>`。

+   `org.opencontainers.image.url`：这应该是一个可以找到有关图像更多信息的 URL。例如，[`github.com/errm/kubegratulations`](https://github.com/errm/kubegratulations)。

+   `org.opencontainers.image.documentation`：这应该是一个可以找到有关图像文档的 URL。例如，[`github.com/errm/kubegratulations/wiki`](https://github.com/errm/kubegratulations/wiki)。

+   `org.opencontainers.image.source`：这应该是一个 URL，可以在其中找到用于构建镜像的源代码。您可以使用它来链接到版本控制存储库上的项目页面，例如 GitHub、GitLab 或 Bitbucket。例如，[`github.com/errm/kubegratulations`](https://github.com/errm/kubegratulations)。

+   `org.opencontainers.image.version`：这可以是打包在此镜像中的软件的语义版本，也可以是您的 VCS 中使用的标签或标记。例如，`1.4.7`。

+   `org.opencontainers.image.revision`：这应该是对您的 VCS 中的修订的引用，例如 Git 提交 SHA。例如，`e2f3bbdf80acd3c96a68ace41a4ac699c203a6a4`。

+   `org.opencontainers.image.vendor`：这应该是分发镜像的组织或个人的名称。例如，**Apache Software Foundation**（**ASF**）。

+   `org.opencontainers.image.licenses`：如果您的镜像包含受特定许可证覆盖的软件，您可以在这里列出它们。您应该使用 SPDX 标识符来引用许可证。您可以在[`spdx.org/licenses/`](https://spdx.org/licenses/)找到完整的列表。例如，`Apache-2.0`。

# 总结

在这一章中，我们学习了如何轻松地在 AWS 上配置 Docker 注册表，以可复制和防错的方式存储我们应用程序的镜像，使用 ECR。

我们发现了如何从我们自己的工作站推送镜像，如何使用 IAM 权限限制对我们镜像的访问，以及如何允许 Kubernetes 直接从 ECR 拉取容器镜像。

您现在应该了解了几种标记镜像的策略，并知道如何向镜像添加附加标签，以存储有关其内容的元数据，并且您已经了解了 Open Container Initiative 镜像规范推荐的标准标签。
