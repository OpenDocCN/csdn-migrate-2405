# 精通 Kubernetes（四）

> 原文：[`zh.annas-archive.org/md5/0FB6BD53079686F120215D277D8C163C`](https://zh.annas-archive.org/md5/0FB6BD53079686F120215D277D8C163C)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：滚动更新、可伸缩性和配额

在本章中，我们将探讨 Kubernetes 提供的自动 Pod 可伸缩性，以及它如何影响滚动更新，以及它如何与配额交互。我们将涉及重要的供应主题，以及如何选择和管理集群的大小。最后，我们将介绍 Kubernetes 团队如何测试 5000 节点集群的极限。以下是我们将涵盖的主要内容：

+   水平 Pod 自动缩放器

+   使用自动缩放执行滚动更新

+   使用配额和限制处理稀缺资源

+   推动 Kubernetes 性能的边界

在本章结束时，您将能够规划一个大规模的集群，经济地进行供应，并就性能、成本和可用性之间的各种权衡做出明智的决策。您还将了解如何设置水平 Pod 自动缩放，并聪明地使用资源配额，让 Kubernetes 自动处理体积的间歇性波动。

# 水平 Pod 自动缩放

Kubernetes 可以监视您的 Pod，并在 CPU 利用率或其他指标超过阈值时对其进行扩展。自动缩放资源指定了细节（CPU 百分比，检查频率），相应的自动缩放控制器会调整副本的数量，如果需要的话。

以下图表说明了不同参与者及其关系：

！[](Images/d2b4b9da-15eb-42e9-b9da-71eb36db89b1.png)

正如您所看到的，水平 Pod 自动缩放器不会直接创建或销毁 Pod。相反，它依赖于复制控制器或部署资源。这非常聪明，因为您不需要处理自动缩放与复制控制器或部署尝试扩展 Pod 数量而不知道自动缩放器的努力之间的冲突。

自动缩放器会自动执行我们以前必须自己执行的操作。如果没有自动缩放器，如果我们有一个副本控制器，副本设置为`3`，但我们确定基于平均 CPU 利用率实际上需要`4`，那么我们将把副本控制器从`3`更新到`4`，并继续手动监视所有 Pod 中的 CPU 利用率。自动缩放器会为我们完成这项工作。

# 声明水平 Pod 自动缩放器

要声明水平 Pod 自动缩放器，我们需要一个复制控制器或部署，以及一个自动缩放资源。这是一个简单的复制控制器，配置为维护三个`nginx` Pod：

```
apiVersion: v1 
kind: ReplicationController 
metadata: 
   name: nginx 
spec: 
   replicas: 3 
   template: 
     metadata: 
       labels: 
         run: nginx 
     spec: 
       containers: 
       - name: nginx 
         image: nginx 
         ports: 
         - containerPort: 80 
```

`autoscaling`资源引用了`scaleTargetRef`中的 NGINX 复制控制器：

```
apiVersion: autoscaling/v1 
kind: HorizontalPodAutoscaler 
metadata: 
  name: nginx 
  namespace: default 
spec: 
  maxReplicas: 4 
  minReplicas: 2 
  targetCPUUtilizationPercentage: 90 
  scaleTargetRef: 
    apiVersion: v1 
    kind: ReplicationController 
    name: nginx 
```

`minReplicas`和`maxReplicas`指定了扩展的范围。这是为了避免因某些问题而发生的失控情况。想象一下，由于某个错误，每个 pod 立即使用 100%的 CPU，而不考虑实际负载。如果没有`maxReplicas`限制，Kubernetes 将不断创建更多的 pod，直到耗尽所有集群资源。如果我们在具有自动缩放 VM 的云环境中运行，那么我们将产生巨大的成本。这个问题的另一面是，如果没有`minReplicas`并且活动出现了停滞，那么所有的 pod 都可能被终止，当新的请求进来时，所有的 pod 都将被重新创建和调度。如果存在开关型活动模式，那么这个循环可能会重复多次。保持最小数量的副本运行可以平滑这种现象。在前面的例子中，`minReplicas`设置为`2`，`maxReplicas`设置为`4`。Kubernetes 将确保始终有`2`到`4`个 NGINX 实例在运行。

**目标 CPU**利用率百分比是一个冗长的词。让我们把它缩写为**TCUP**。您可以指定一个像 80%这样的单个数字。如果平均负载在 TCUP 周围徘徊，这可能会导致不断的抖动。Kubernetes 将频繁地在增加更多副本和删除副本之间交替。这通常不是期望的行为。为了解决这个问题，您可以为扩展或缩减指定延迟。`kube-controller-manager`有两个标志来支持这一点：

+   `--horizontal-pod-autoscaler-downscale-delay`：此选项的值是一个持续时间，指定了在当前操作完成后，自动缩放器必须等待多长时间才能执行另一个缩减操作。默认值为 5 分钟（5m0s）。

+   `--horizontal-pod-autoscaler-upscale-delay`：此选项的值是一个持续时间，指定了在当前操作完成后，自动缩放器必须等待多长时间才能执行另一个扩展操作。默认值为 3 分钟（3m0s）。

# 自定义指标

CPU 利用率是一个重要的指标，用于判断是否应该扩展受到过多请求的 Pod，或者它们是否大部分处于空闲状态并且可以缩小规模。但是 CPU 并不是唯一的，有时甚至不是最好的指标。内存可能是限制因素，还有更专业的指标，例如 Pod 内部磁盘队列的深度、请求的平均延迟或服务超时的平均次数。

水平 Pod 自定义指标在 1.2 版本中作为 alpha 扩展添加。在 1.6 版本中，它们升级为 beta 状态。现在可以根据多个自定义指标自动调整 Pod 的规模。自动缩放器将评估所有指标，并根据所需的最大副本数量进行自动缩放，因此会尊重所有指标的要求。

# 使用自定义指标

使用自定义指标的水平 Pod 自动缩放器在启动集群时需要进行一些配置。首先，您需要启用 API 聚合层。然后，您需要注册您的资源指标 API 和自定义指标 API。Heapster 提供了一个资源指标 API 的实现，您可以使用。只需使用`--api-server`标志启动 Heapster，并将其设置为`true`。您需要运行一个单独的服务器来公开自定义指标 API。一个很好的起点是这个：[`github.com/kubernetes-incubator/custom-metrics-apiserver`](https://github.com/kubernetes-incubator/custom-metrics-apiserver)。

下一步是使用以下标志启动`kube-controller-manager`：

```
--horizontal-pod-autoscaler-use-rest-clients=true
--kubeconfig <path-to-kubeconfig> OR --master <ip-address-of-apiserver>  
```

如果同时指定了`--master`标志和`--kubeconfig`标志，则`--master`标志将覆盖`--kubeconfig`标志。这些标志指定了 API 聚合层的位置，允许控制器管理器与 API 服务器通信。

在 Kubernetes 1.7 中，Kubernetes 提供的标准聚合层与`kube-apiserver`一起运行，因此可以使用以下命令找到目标 IP 地址：

```
> kubectl get pods --selector k8s-app=kube-apiserver --namespace kube-system -o jsonpath='{.items[0].status.podIP}'  
```

# 使用 kubectl 进行自动缩放

`kubectl`可以使用标准的`create`命令并接受一个配置文件来创建自动缩放资源。但是`kubectl`还有一个特殊的命令`autoscale`，可以让您轻松地在一个命令中设置自动缩放器，而无需特殊的配置文件：

1.  首先，让我们启动一个复制控制器，确保有三个简单 Pod 的副本，这些 Pod 只运行一个无限的`bash-loop`：

```
apiVersion: v1 
kind: ReplicationController 
metadata: 
   name: bash-loop-rc 
spec: 
   replicas: 3 
   template: 
     metadata: 
       labels: 
         name: bash-loop-rc 
     spec: 
       containers: 
         - name: bash-loop 
           image: ubuntu 
           command: ["/bin/bash", "-c", "while true; do sleep 10;   
                      done"] 
```

1.  让我们创建一个复制控制器：

```
     > kubectl create -f bash-loop-rc.yaml
     replicationcontroller "bash-loop-rc" created 
```

1.  以下是生成的复制控制器：

```
     > kubectl get rc
     NAME              DESIRED   CURRENT   READY     AGE
     bash-loop-rc        3          3       3         1m  
```

1.  您可以看到所需和当前计数都是三，意味着有三个 pod 正在运行。让我们确保一下：

```
     > kubectl get pods
     NAME                     READY    STATUS    RESTARTS    AGE
     bash-loop-rc-8h59t        1/1     Running    0          50s
     bash-loop-rc-lsvtd        1/1     Running    0          50s
     bash-loop-rc-z7wt5        1/1     Running    0          50s  
```

1.  现在，让我们创建一个自动缩放器。为了使其有趣，我们将将最小副本数设置为 `4`，最大副本数设置为 `6`：

```
 > kubectl autoscale rc bash-loop-rc --min=4 --max=6 --cpu- percent=50
replicationcontroller "bash-loop-rc" autoscaled
```

1.  这是生成的水平 pod 自动缩放器（您可以使用 `hpa`）。它显示了引用的复制控制器、目标和当前 CPU 百分比，以及最小/最大 pod 数。名称与引用的复制控制器匹配：

```
 > kubectl get hpa
 NAME          REFERENCE    TARGETS  MINPODS  MAXPODS  REPLICAS  AGE bash-loop-rc  bash-loop-rc  50%     4        6         4        16m
```

1.  最初，复制控制器被设置为具有三个副本，但自动缩放器的最小值为四个 pod。这对复制控制器有什么影响？没错。现在所需的副本数是四个。如果平均 CPU 利用率超过 50％，则可能会增加到五个，甚至六个：

```
     > kubectl get rc
     NAME              DESIRED  CURRENT  READY    AGE
     bash-loop-rc       4       4        4        21m
```

1.  为了确保一切正常运行，让我们再看一下 pod。请注意，由于自动缩放，创建了一个新的 pod（17 分钟前）：

```
     > kubectl get pods
     NAME                READY   STATUS    RESTARTS   AGE
     bash-loop-rc-8h59t   1/1     Running   0         21m
     bash-loop-rc-gjv4k   1/1     Running   0         17m
     bash-loop-rc-lsvtd    1/1    Running   0         21m
     bash-loop-rc-z7wt5   1/1     Running   0         21m
```

1.  当我们删除水平 pod 自动缩放器时，复制控制器会保留最后所需的副本数（在这种情况下为四个）。没有人记得复制控制器是用三个副本创建的：

```
     > kubectl  delete hpa bash-loop-rc
     horizontalpodautoscaler "bash-loop-rc" deleted 
```

1.  正如您所看到的，即使自动缩放器消失，复制控制器也没有重置，仍然保持四个 pod：

```
     > kubectl get rc
     NAME              DESIRED   CURRENT   READY      AGE
     bash-loop-rc       4           4       4         28m
```

让我们尝试其他方法。如果我们创建一个新的水平 pod 自动缩放器，范围为 `2` 到 `6`，并且相同的 CPU 目标为 `50`％，会发生什么？

```
> kubectl autoscale rc bash-loop-rc --min=2 --max=6 --cpu-percent=50
    replicationcontroller "bash-loop-rc" autoscaled  
```

好吧，复制控制器仍然保持其四个副本，这在范围内：

```
> kubectl get rc
NAME           DESIRED   CURRENT   READY     AGE
bash-loop-rc   4         4         4         29m  
```

然而，实际 CPU 利用率为零，或接近零。副本计数应该已经缩减到两个副本，但由于水平 pod 自动缩放器没有从 Heapster 接收到 CPU 指标，它不知道需要缩减复制控制器中的副本数。

# 使用自动缩放进行滚动更新

滚动更新是管理大型集群的基石。Kubernetes 支持在复制控制器级别和使用部署进行滚动更新。使用复制控制器进行滚动更新与水平 pod 自动缩放器不兼容。原因是在滚动部署期间，会创建一个新的复制控制器，而水平 pod 自动缩放器仍然绑定在旧的复制控制器上。不幸的是，直观的 `kubectl rolling-update` 命令会触发复制控制器的滚动更新。

由于滚动更新是如此重要的功能，我建议您始终将水平 Pod 自动缩放器绑定到部署对象，而不是复制控制器或副本集。当水平 Pod 自动缩放器绑定到部署时，它可以设置部署规范中的副本，并让部署负责必要的底层滚动更新和复制。

这是我们用于部署`hue-reminders`服务的部署配置文件：

```
apiVersion: extensions/v1beta1 
kind: Deployment 
metadata: 
  name: hue-reminders 
spec: 
  replicas: 2   
  template: 
    metadata: 
      name: hue-reminders 
      labels: 
        app: hue-reminders 
    spec:     
      containers: 
      - name: hue-reminders 
        image: g1g1/hue-reminders:v2.2     
        ports: 
        - containerPort: 80  
```

为了支持自动缩放并确保我们始终有`10`到`15`个实例在运行，我们可以创建一个`autoscaler`配置文件：

```
apiVersion: autoscaling/v1 
 kind: HorizontalPodAutoscaler 
 metadata: 
   name: hue-reminders 
   namespace: default 
 spec: 
   maxReplicas: 15 
   minReplicas: 10 
   targetCPUUtilizationPercentage: 90 
   scaleTargetRef: 
     apiVersion: v1 
     kind: Deployment 
     name: hue-reminders 
```

`scaleTargetRef`字段的`kind`现在是`Deployment`，而不是`ReplicationController`。这很重要，因为我们可能有一个同名的复制控制器。为了消除歧义并确保水平 Pod 自动缩放器绑定到正确的对象，`kind`和`name`必须匹配。

或者，我们可以使用`kubectl autoscale`命令：

```
> kubectl autoscale deployment hue-reminders --min=10--max=15
--cpu-percent=90  
```

# 处理稀缺资源的限制和配额

随着水平 Pod 自动缩放器动态创建 pod，我们需要考虑如何管理我们的资源。调度很容易失控，资源的低效使用是一个真正的问题。有几个因素可以以微妙的方式相互作用：

+   整个集群的容量

+   每个节点的资源粒度

+   按命名空间划分工作负载

+   DaemonSets

+   StatefulSets

+   亲和性、反亲和性、污点和容忍

首先，让我们了解核心问题。Kubernetes 调度器在调度 pod 时必须考虑所有这些因素。如果存在冲突或许多重叠的要求，那么 Kubernetes 可能会在安排新的 pod 时遇到问题。例如，一个非常极端但简单的情况是，一个守护进程集在每个节点上运行一个需要 50%可用内存的 pod。现在，Kubernetes 无法安排任何需要超过 50%内存的 pod，因为守护进程集 pod 具有优先级。即使您提供新节点，守护进程集也会立即占用一半的内存。

Stateful sets 类似于守护程序集，因为它们需要新节点来扩展。向 Stateful set 添加新成员的触发器是数据的增长，但影响是从 Kubernetes 可用于调度其他成员的池中获取资源。在多租户情况下，嘈杂的邻居问题可能会在供应或资源分配上出现。您可能会在命名空间中精确地计划不同 pod 和它们的资源需求之间的比例，但您与来自其他命名空间的邻居共享实际节点，甚至可能无法看到。

大多数这些问题可以通过谨慎使用命名空间资源配额和对跨多个资源类型（如 CPU、内存和存储）的集群容量进行仔细管理来缓解。

# 启用资源配额

大多数 Kubernetes 发行版都支持开箱即用的资源配额。API 服务器的`--admission-control`标志必须将`ResourceQuota`作为其参数之一。您还必须创建一个`ResourceQuota`对象来强制执行它。请注意，每个命名空间最多只能有一个`ResourceQuota`对象，以防止潜在的冲突。这是由 Kubernetes 强制执行的。

# 资源配额类型

我们可以管理和控制不同类型的配额。这些类别包括计算、存储和对象。

# 计算资源配额

计算资源是 CPU 和内存。对于每个资源，您可以指定限制或请求一定数量。以下是与计算相关的字段列表。请注意，`requests.cpu`可以简单地指定为`cpu`，`requests.memory`可以简单地指定为 memory：

+   `limits.cpu`: 在非终端状态的所有 pod 中，CPU 限制的总和不能超过此值

+   `limits.memory`: 在非终端状态的所有 pod 中，内存限制的总和不能超过此值

+   `requests.cpu`: 在非终端状态的所有 pod 中，CPU 请求的总和不能超过此值

+   `requests.memory`: 在非终端状态的所有 pod 中，内存请求的总和不能超过此值

# 存储资源配额

存储资源配额类型有点复杂。您可以限制每个命名空间的两个实体：存储量和持久卷索赔的数量。但是，除了全局设置总存储配额或持久卷索赔总数之外，您还可以按`storage`类别设置。`storage`类别资源配额的表示法有点冗长，但它可以完成工作：

+   `requests.storage`: 在所有持久卷索赔中，存储请求的总和不能超过此值

+   `persistentvolumeclaims`: 可以存在于命名空间中的持久卷索赔的总数

+   `<storage-class>.storageclass.storage.k8s.io/requests.storage`: 与`storage-class-name`相关联的所有持久卷索赔中，存储请求的总和不能超过此值

+   `<storage-class>.storageclass.storage.k8s.io/persistentvolumeclaims`: 与`storage-class-name`相关联的所有持久卷索赔中，可以存在于命名空间中的持久卷索赔的总数

Kubernetes 1.8 还增加了对临时存储配额的 alpha 支持：

+   `requests.ephemeral-storage`: 在命名空间中的所有 Pod 中，本地临时存储请求的总和不能超过此值

+   `limits.ephemeral-storage`: 在命名空间中的所有 Pod 中，本地临时存储限制的总和不能超过此值

# 对象计数配额

Kubernetes 还有另一类资源配额，即 API 对象。我猜想目标是保护 Kubernetes API 服务器免受管理太多对象的影响。请记住，Kubernetes 在幕后做了很多工作。它经常需要查询多个对象来进行身份验证、授权，并确保操作不违反可能存在的许多策略。一个简单的例子是基于复制控制器的 Pod 调度。想象一下，您有 10 亿个复制控制器对象。也许您只有三个 Pod，大多数复制控制器都没有副本。但是，Kubernetes 将花费大量时间来验证这 10 亿个复制控制器确实没有其 Pod 模板的副本，并且它们不需要终止任何 Pod。这是一个极端的例子，但这个概念适用。太多的 API 对象意味着 Kubernetes 需要做很多工作。

可以限制的对象的超额有点零散。例如，可以限制复制控制器的数量，但不能限制副本集的数量，副本集几乎是复制控制器的改进版本，如果有太多副本集存在，它们可能会造成完全相同的破坏。

最明显的遗漏是命名空间。对命名空间的数量没有限制。由于所有限制都是针对命名空间的，因此通过创建太多的命名空间，可以轻松地压倒 Kubernetes，因为每个命名空间只有少量的 API 对象。

以下是所有支持的对象：

+   配置映射：可以存在于命名空间中的配置映射的总数。

+   持久卷索赔：可以存在于命名空间中的持久卷索赔的总数。

+   Pods：可以存在于命名空间中的非终端状态的 Pod 的总数。如果`status.phase`在（`Failed`，`Succeeded`）中为`true`，则 Pod 处于终端状态。

+   复制控制器：可以存在于命名空间中的复制控制器的总数。

+   资源配额：可以存在于命名空间中的资源配额的总数。

+   服务：可以存在于命名空间中的服务的总数。

+   服务负载均衡器：可以存在于命名空间中的负载均衡器服务的总数。

+   服务节点端口：可以存在于命名空间中的节点端口服务的总数。

+   秘密：可以存在于命名空间中的秘密的总数。

# 配额范围

一些资源，如 Pod，可能处于不同的状态，为这些不同的状态设置不同的配额是有用的。例如，如果有许多正在终止的 Pod（这在滚动更新期间经常发生），即使总数超过配额，也可以创建更多的 Pod。这可以通过仅将`pod`对象`计数配额`应用于`非终止`的 Pod 来实现。以下是现有的范围：

+   终止：匹配`spec.activeDeadlineSeconds >= 0`的 Pod。

+   非终止：匹配`spec.activeDeadlineSeconds`为空的 Pod。

+   最佳努力：匹配具有最佳努力的服务质量的 Pod

+   非最佳努力：匹配没有最佳努力服务质量的 Pod

虽然`BestEffort`范围仅适用于 Pod，但`Terminating`，`NotTerminating`和`NotBestEffort`范围也适用于 CPU 和内存。这很有趣，因为资源配额限制可以阻止 Pod 终止。以下是支持的对象：

+   CPU

+   限制 CPU

+   限制内存

+   内存

+   `pods`

+   `requests.cpu`

+   `requests.memory`

# 请求和限制

在资源配额的背景下，请求和限制的含义是它要求容器明确指定目标属性。这样，Kubernetes 可以管理总配额，因为它确切地知道为每个容器分配了什么范围的资源。

# 使用配额

首先让我们创建一个`namespace`：

```
> kubectl create namespace ns
namespace "ns" created  
```

# 使用特定于命名空间的上下文

在与默认值不同的命名空间中工作时，我更喜欢使用`context`，这样我就不必为每个命令不断输入`--namespace=ns`：

```
> kubectl config set-context ns --cluster=minikube --user=minikube --namespace=ns
Context "ns" set.
> kubectl config use-context ns
Switched to context "ns".  
```

# 创建配额

1.  创建一个`compute quota`对象：

```
    apiVersion: v1
    kind: ResourceQuota
    metadata:
      name: compute-quota
    spec:
      hard:
        pods: "2"
        requests.cpu: "1"
        requests.memory: 20Mi
        limits.cpu: "2"
        limits.memory: 2Gi

    > kubectl create -f compute-quota.yaml
    resourcequota "compute-quota" created
```

1.  接下来，让我们添加一个`count quota`对象：

```
    apiVersion: v1
    kind: ResourceQuota
    metadata:
      name: object-counts-quota
    spec:
      hard:
        configmaps: "10"
        persistentvolumeclaims: "4"
        replicationcontrollers: "20"
        secrets: "10"
        services: "10"
        services.loadbalancers: "2"

    > kubectl create -f object-count-quota.yaml
    resourcequota "object-counts-quota" created 
```

1.  我们可以观察所有的配额：

```
    > kubectl get quota
    NAME                     AGE
    compute-resources        17m
    object-counts            15m
```

1.  我们甚至可以使用`describe`获取所有信息：

```
    > kubectl describe quota compute-quota
    Name:            compute-quota
    Namespace:       ns
    Resource         Used  Hard
    --------          ----     ----
    limits.cpu          0        2
    limits.memory       0        2Gi
    pods                0        2
    requests.cpu        0        1
    requests.memory     0        20Mi

    > kubectl describe quota object-counts-quota
    Name:                   object-counts-quota
    Namespace:              ns
    Resource                Used    Hard
    --------                ----    ----
    configmaps              0       10
    persistentvolumeclaims  0       4
    replicationcontrollers  0       20
    secrets                 1       10
    services                0       10
    services.loadbalancers  0       2
```

这个视图让我们立即了解集群中重要资源的全局资源使用情况，而无需深入研究太多单独的对象。

1.  让我们向我们的命名空间添加一个 NGINX 服务器：

```
    > kubectl run nginx --image=nginx --replicas=1 
    deployment "nginx" created
    > kubectl get pods
    No resources found.
```

1.  哦哦。没有找到资源。但是在创建`deployment`时没有错误。让我们检查一下`deployment`资源：

```
    > kubectl describe deployment nginx
    Name:                   nginx
    Namespace:              ns
    CreationTimestamp:      Sun, 11 Feb 2018 16:04:42 -0800
    Labels:                 run=nginx
    Annotations:            deployment.kubernetes.io/revision=1
    Selector:               run=nginx
    Replicas:               1 desired | 0 updated | 0 total | 0 available | 1 unavailable
    StrategyType:           RollingUpdate
    MinReadySeconds:        0
    RollingUpdateStrategy:  1 max unavailable, 1 max surge
    Pod Template:
      Labels:  run=nginx
      Containers:
       nginx:
        Image:        nginx
        Port:         <none>
        Environment:  <none>
        Mounts:       <none>
      Volumes:        <none>
    Conditions:
      Type                   Status  Reason
      ----                   ------     ------
      Available            True     MinimumReplicasAvailable
      ReplicaFailure       True     FailedCreate
    OldReplicaSets:       <none>
    NewReplicaSet:     nginx-8586cf59 (0/1 replicas created)
    Events:
      Type    Reason       Age  From                 Message
      ----        ------               ----  ----              -------
Normal  ScalingReplicaSet  16m  deployment-controller  Scaled up replica set nginx-8586cf59 to 1
```

在`conditions`部分就在那里。`ReplicaFailure`状态是`True`，原因是`FailedCreate`。您可以看到部署创建了一个名为`nginx-8586cf59`的新副本集，但它无法创建它应该创建的 pod。我们仍然不知道原因。让我们检查一下副本集：

```
    > kubectl describe replicaset nginx-8586cf59
    Name:           nginx-8586cf59
    Namespace:      ns
    Selector:       pod-template-hash=41427915,run=nginx
    Labels:         pod-template-hash=41427915
                    run=nginx
    Annotations:    deployment.kubernetes.io/desired-replicas=1
                    deployment.kubernetes.io/max-replicas=2
                    deployment.kubernetes.io/revision=1
    Controlled By:  Deployment/nginx
    Replicas:       0 current / 1 desired
    Pods Status:    0 Running / 0 Waiting / 0 Succeeded / 0 Failed
    Conditions:
      Type             Status  Reason
      ----             ------  ------
      ReplicaFailure   True    FailedCreate
    Events:
      Type     Reason        Age                From                   Message
      ----     ------        ----               ----                   -------
      Warning  FailedCreate  17m (x8 over 22m)  replicaset-controller  (combined from similar events): Error creating: pods "nginx-8586cf59-sdwxj" is forbidden: failed quota: compute-quota: must specify limits.cpu,limits.memory,requests.cpu,requests.memory  
```

输出非常宽，所以它跨越了几行，但是消息非常清晰。由于命名空间中有计算配额，因此每个容器必须指定其 CPU、内存请求和限制。配额控制器必须考虑每个容器的计算资源使用情况，以确保总命名空间配额得到尊重。

好的。我们理解了问题，但如何解决呢？一种方法是为我们想要使用的每种 pod 类型创建一个专用的`deployment`对象，并仔细设置 CPU 和内存请求和限制。但如果我们不确定呢？如果有很多 pod 类型，我们不想管理一堆`deployment`配置文件呢？

另一个解决方案是在运行`deployment`时在命令行上指定限制：

```
    > kubectl run nginx \
      --image=nginx \
      --replicas=1 \
      --requests=cpu=100m,memory=4Mi \
      --limits=cpu=200m,memory=8Mi \
      --namespace=ns
```

这样做是有效的，但是通过大量参数动态创建部署是管理集群的一种非常脆弱的方式：

```
    > kubectl get pods
    NAME                     READY     STATUS    RESTARTS   AGE
    nginx-2199160687-zkc2h   1/1       Running   0          2m 
```

# 使用默认计算配额的限制范围

1.  更好的方法是指定默认的计算限制。输入限制范围。这是一个设置一些容器默认值的配置文件：

```
    apiVersion: v1
    kind: LimitRange
    metadata:
      name: limits
    spec:
      limits:
      - default:
          cpu: 200m
          memory: 6Mi
        defaultRequest:
          cpu: 100m
          memory: 5Mi
    type: Container 

    > kubectl create -f limits.yaml
    limitrange "limits" created  
```

1.  这是当前默认的`limits`：

```
> kubectl describe limits limitsName:  limits
Namespace:  ns
Type Resource Min Max Default Request Default Limit Max Limit/Request Ratio
----          --------        ---     ---     ---------------            -------------     -----------------------
Container cpu     -   -   100m         200m       -
Container memory    -       -      5Mi      6Mi                 -
```

1.  现在，让我们再次运行 NGINX，而不指定任何 CPU 或内存请求和限制。但首先，让我们删除当前的 NGINX 部署：

```
 > kubectl delete deployment nginx
 deployment "nginx" deleted
 > kubectl run nginx --image=nginx --replicas=1
 deployment "nginx" created
```

1.  让我们看看 Pod 是否已创建。是的，它已经创建了：

```
         > kubectl get pods
         NAME                   READY     STATUS    RESTARTS  AGE
         nginx-8586cf59-p4dp4   1/1       Running    0        16m
```

# 选择和管理集群容量

通过 Kubernetes 的水平 Pod 自动缩放、守护进程集、有状态集和配额，我们可以扩展和控制我们的 Pod、存储和其他对象。然而，最终，我们受限于 Kubernetes 集群可用的物理（虚拟）资源。如果所有节点的容量都达到 100%，您需要向集群添加更多节点。没有其他办法。Kubernetes 将无法扩展。另一方面，如果您的工作负载非常动态，那么 Kubernetes 可以缩小您的 Pod，但如果您不相应地缩小节点，您仍然需要支付额外的容量费用。在云中，您可以停止和启动实例。

# 选择您的节点类型

最简单的解决方案是选择一个已知数量的 CPU、内存和本地存储的单一节点类型。但这通常不是最有效和成本效益的解决方案。这使得容量规划变得简单，因为唯一的问题是需要多少个节点。每当添加一个节点，就会向集群添加已知数量的 CPU 和内存，但大多数 Kubernetes 集群和集群内的组件处理不同的工作负载。我们可能有一个流处理管道，许多 Pod 在一个地方接收一些数据并对其进行处理。这种工作负载需要大量 CPU，可能需要大量内存，也可能不需要。其他组件，如分布式内存缓存，需要大量内存，但几乎不需要 CPU。其他组件，如 Cassandra 集群，需要每个节点连接多个 SSD 磁盘。

对于每种类型的节点，您应考虑适当的标记和确保 Kubernetes 调度设计为在该节点类型上运行的 Pod。

# 选择您的存储解决方案

存储是扩展集群的重要因素。有三种可扩展的存储解决方案：

+   自定义解决方案

+   使用您的云平台存储解决方案

+   使用集群外解决方案

当您使用自定义解决方案时，在 Kubernetes 集群中安装某种存储解决方案。优点是灵活性和完全控制，但您必须自行管理和扩展。

当您使用云平台存储解决方案时，您可以获得很多开箱即用的功能，但您失去了控制，通常需要支付更多费用，并且根据服务的不同，您可能会被锁定在该提供商那里。

当你使用集群外的解决方案时，数据传输的性能和成本可能会更大。通常情况下，如果你需要与现有系统集成，你会选择这个选项。

当然，大型集群可能会有来自所有类别的多个数据存储。这是你必须做出的最关键的决定之一，你的存储需求可能会随着时间的推移而发生变化和演变。

# 权衡成本和响应时间

如果金钱不是问题，你可以过度配置你的集群。每个节点都将拥有最佳的硬件配置，你将拥有比处理工作负载所需更多的节点，以及大量可用的存储空间。猜猜？金钱总是一个问题！

当你刚开始并且你的集群处理的流量不多时，你可能会通过过度配置来解决问题。即使大部分时间只需要两个节点，你可能只运行五个节点。将一切乘以 1,000，如果你有成千上万台空闲机器和宠字节的空闲存储，有人会来问问题。

好吧。所以，你仔细测量和优化，你得到了每个资源的 99.99999%利用率。恭喜，你刚创造了一个系统，它无法处理额外的负载或单个节点的故障，而不会丢弃请求或延迟响应。

你需要找到一个折中的方法。了解你的工作负载的典型波动，并考虑过剩容量与减少响应时间或处理能力之间的成本效益比。

有时，如果你有严格的可用性和可靠性要求，你可以通过设计在系统中构建冗余来过度配置。例如，你希望能够在没有停机和没有明显影响的情况下热插拔失败的组件。也许你甚至不能失去一笔交易。在这种情况下，你将为所有关键组件提供实时备份，这种额外的容量可以用来缓解临时波动，而无需任何特殊操作。

# 有效地使用多个节点配置

有效的容量规划需要你了解系统的使用模式以及每个组件可以处理的负载。这可能包括系统内部产生的大量数据流。当你对典型的工作负载有很好的理解时，你可以查看工作流程以及哪些组件处理负载的哪些部分。然后你可以计算 Pod 的数量和它们的资源需求。根据我的经验，有一些相对固定的工作负载，一些可以可预测变化的工作负载（比如办公时间与非办公时间），然后你有一些完全疯狂的工作负载，表现得不稳定。你必须根据每个工作负载进行规划，并且你可以设计几个节点配置系列，用于安排与特定工作负载匹配的 Pod。

# 受益于弹性云资源

大多数云提供商都可以让你自动扩展实例，这是对 Kubernetes 水平 Pod 自动缩放的完美补充。如果你使用云存储，它也会在你无需做任何事情的情况下神奇地增长。然而，有一些需要注意的地方。

# 自动缩放实例

所有大型云提供商都已经实现了实例自动缩放。虽然有一些差异，但基于 CPU 利用率的扩展和缩减始终可用，有时也可以使用自定义指标。有时也提供负载均衡。你可以看到，这里与 Kubernetes 有一些重叠。如果你的云提供商没有适当的自动缩放和适当的控制，相对容易自己实现，这样你就可以监控集群资源使用情况并调用云 API 来添加或删除实例。你可以从 Kubernetes 中提取指标。

这是一个图表，显示了基于 CPU 负载监视器添加了两个新实例的情况。

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-k8s/img/997c6242-6b95-4225-b1b3-992e7f12863d.png)

# 注意你的云配额

在与云提供商合作时，一些最让人讨厌的事情是配额。我曾与四个不同的云提供商合作过（AWS，GCP，Azure 和阿里云），总会在某个时候受到配额的限制。配额的存在是为了让云提供商进行自己的容量规划（也是为了保护您免受意外启动 100 万个无法支付的实例），但从您的角度来看，这又是一个可能让您遇到麻烦的事情。想象一下，您设置了一个像魔术一样工作的美丽的自动扩展系统，突然当您达到 100 个节点时，系统不再扩展。您很快发现自己被限制在 100 个节点，并且打开了一个支持请求来增加配额。然而，配额请求必须由人员批准，这可能需要一两天的时间。与此同时，您的系统无法处理负载。

# 谨慎管理区域

云平台按区域和可用性区域组织。某些服务和机器配置仅在某些区域可用。云配额也是在区域级别管理的。区域内数据传输的性能和成本要比跨区域低得多（通常是免费）。在规划您的集群时，您应该仔细考虑您的地理分布策略。如果您需要在多个区域运行您的集群，您可能需要做出一些关于冗余、可用性、性能和成本的艰难决定。

# 考虑 Hyper.sh（和 AWS Fargate）

`Hyper.sh`是一个容器感知的托管服务。您只需启动容器。该服务负责分配硬件。容器在几秒钟内启动。您永远不需要等待几分钟来获取新的虚拟机。Hypernetes 是在 Hyper.sh 上的 Kubernetes，它完全消除了扩展节点的需要，因为在您看来根本没有节点。只有容器（或 Pod）。

在下图中，您可以看到右侧的**Hyper 容器**直接在多租户裸金属容器云上运行：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-k8s/img/061b3cae-185a-4856-8612-506f76e3365c.png)

AWS 最近发布了 Fargate，类似地将底层实例抽象化，并允许您在云中安排容器。与 EKS 结合使用，可能成为部署 Kubernetes 的最流行方式。

# 使用 Kubernetes 推动信封

在本节中，我们将看到 Kubernetes 团队如何将 Kubernetes 推向极限。这些数字相当说明问题，但一些工具和技术，如 Kubemark，是巧妙的，您甚至可以使用它们来测试您的集群。在野外，有一些拥有 3,000 个节点的 Kubernetes 集群。在 CERN，OpenStack 团队实现了每秒 2 百万次请求：

[`superuser.openstack.org/articles/scaling-magnum-and-kubernetes-2-million-requests-per-second/`](http://superuser.openstack.org/articles/scaling-magnum-and-kubernetes-2-million-requests-per-second/)。

Mirantis 在其扩展实验室进行了性能和扩展测试，部署了 5,000 个 Kubernetes 节点（在虚拟机中）在 500 台物理服务器上。

有关 Mirantis 的更多详细信息，请参阅：[`bit.ly/2oijqQY`](http://bit.ly/2oijqQY)。

OpenAI 将其机器学习 Kubernetes 集群扩展到 2,500 个节点，并学到了一些宝贵的经验教训，比如注意日志代理的查询负载，并将事件存储在单独的`etcd`集群中：

[`blog.openai.com/scaling-kubernetes-to-2500-nodes/`](https://blog.openai.com/scaling-kubernetes-to-2500-nodes/)

在本节结束时，您将欣赏到改进大规模 Kubernetes 所需的努力和创造力，您将了解单个 Kubernetes 集群的极限以及预期的性能，您将深入了解一些工具和技术，可以帮助您评估自己的 Kubernetes 集群的性能。

# 改进 Kubernetes 的性能和可扩展性

Kubernetes 团队在 Kubernetes 1.6 中大力专注于性能和可扩展性。当 Kubernetes 1.2 发布时，它支持 Kubernetes 服务水平目标内的最多 1,000 个节点的集群。Kubernetes 1.3 将该数字增加到 2,000 个节点，而 Kubernetes 1.6 将其提高到惊人的 5,000 个节点每个集群。我们稍后会详细介绍这些数字，但首先让我们来看看 Kubernetes 是如何实现这些令人印象深刻的改进的。

# 在 API 服务器中缓存读取

Kubernetes 将系统状态保存在 etcd 中，这是非常可靠的，尽管不是超级快速的（尽管 etcd3 专门提供了巨大的改进，以便实现更大的 Kubernetes 集群）。各种 Kubernetes 组件在该状态的快照上操作，并不依赖于实时更新。这一事实允许在一定程度上以一些延迟换取吞吐量。所有快照都曾由 etcd 监视更新。现在，API 服务器具有用于更新状态快照的内存读取缓存。内存读取缓存由 etcd 监视更新。这些方案显著减少了 etcd 的负载，并增加了 API 服务器的整体吞吐量。

# Pod 生命周期事件生成器

增加集群中节点的数量对于水平扩展至关重要，但 Pod 密度也至关重要。Pod 密度是 Kubelet 在一个节点上能够有效管理的 Pod 数量。如果 Pod 密度低，那么你就不能在一个节点上运行太多的 Pod。这意味着你可能无法从更强大的节点（每个节点的 CPU 和内存更多）中受益，因为 Kubelet 将无法管理更多的 Pod。另一种选择是强迫开发人员妥协他们的设计，并创建粗粒度的 Pod，每个 Pod 执行更多的工作。理想情况下，Kubernetes 在 Pod 粒度方面不应该强迫你的决定。Kubernetes 团队非常了解这一点，并投入了大量工作来改善 Pod 密度。

在 Kubernetes 1.1 中，官方（经过测试和宣传）的数量是每个节点 30 个 Pod。我实际上在 Kubernetes 1.1 上每个节点运行了 40 个 Pod，但我付出了过多的 kubelet 开销，这从工作 Pod 中窃取了 CPU。在 Kubernetes 1.2 中，这个数字跳升到每个节点 100 个 Pod。

Kubelet 以自己的 go 例程不断轮询容器运行时，以获取每个 pod 的状态。这给容器运行时带来了很大的压力，因此在性能高峰期会出现可靠性问题，特别是 CPU 利用率方面。解决方案是**Pod 生命周期事件生成器**（**PLEG**）。PLEG 的工作方式是列出所有 pod 和容器的状态，并将其与先前的状态进行比较。这只需要一次，就可以对所有的 pod 和容器进行比较。然后，通过将状态与先前的状态进行比较，PLEG 知道哪些 pod 需要再次同步，并只调用这些 pod。这一变化导致 Kubelet 和容器运行时的 CPU 使用率显著降低了四倍。它还减少了轮询周期，提高了响应性。

以下图表显示了 Kubernetes 1.1 和 Kubernetes 1.2 上**120 个 pod 的 CPU 利用率**。您可以清楚地看到 4 倍的因素：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-k8s/img/233f183e-7dd1-4856-9050-2862a9e5e591.png)

# 使用协议缓冲区对 API 对象进行序列化

API 服务器具有 REST API。REST API 通常使用 JSON 作为其序列化格式，Kubernetes API 服务器也不例外。然而，JSON 序列化意味着将 JSON 编组和解组为本机数据结构。这是一个昂贵的操作。在大规模的 Kubernetes 集群中，许多组件需要频繁查询或更新 API 服务器。所有这些 JSON 解析和组合的成本很快就会累积起来。在 Kubernetes 1.3 中，Kubernetes 团队添加了一个高效的协议缓冲区序列化格式。JSON 格式仍然存在，但 Kubernetes 组件之间的所有内部通信都使用协议缓冲区序列化格式。

# etcd3

Kubernetes 在 Kubernetes 1.6 中从 etcd2 切换到 etcd3。这是一件大事。由于 etcd2 的限制，尤其是与 watch 实现相关的限制，将 Kubernetes 扩展到 5000 个节点是不可能的。Kubernetes 的可扩展性需求推动了 etcd3 的许多改进，因为 CoreOS 将 Kubernetes 作为一个衡量标准。一些重要的项目如下：

+   GRPC 而不是 REST-etcd2 具有 REST API，etcd3 具有 gRPC API（以及通过 gRPC 网关的 REST API）。在 gRPC 基础上的 http/2 协议可以使用单个 TCP 连接来处理多个请求和响应流。

+   租约而不是 TTL-etcd2 使用**生存时间**（**TTL**）来过期键，而 etcd3 使用带有 TTL 的租约，多个键可以共享同一个键。这显著减少了保持活动的流量。

+   etcd3 的 watch 实现利用了 GRPC 双向流，并维护单个 TCP 连接以发送多个事件，这至少减少了一个数量级的内存占用。

+   使用 etcd3，Kubernetes 开始将所有状态存储为 protobug，这消除了许多浪费的 JSON 序列化开销。

# 其他优化

Kubernetes 团队进行了许多其他优化：

+   优化调度程序（导致调度吞吐量提高了 5-10 倍）

+   将所有控制器切换到新的推荐设计，使用共享通知器，这减少了控制器管理器的资源消耗-有关详细信息，请参阅此文档[`github.com/kubernetes/community/blob/master/contributors/devel/controllers.md`](https://github.com/kubernetes/community/blob/master/contributors/devel/controllers.md)

+   优化 API 服务器中的单个操作（转换、深拷贝、补丁）

+   减少 API 服务器中的内存分配（这对 API 调用的延迟有显著影响）

# 测量 Kubernetes 的性能和可伸缩性

为了提高性能和可伸缩性，您需要清楚地知道您想要改进什么，以及如何去衡量这些改进。您还必须确保在追求性能和可伸缩性的过程中不违反基本属性和保证。我喜欢性能改进的地方在于它们通常可以免费为您带来可伸缩性的改进。例如，如果一个 pod 需要节点的 50% CPU 来完成其工作，而您改进了性能，使得该 pod 只需要 33% 的 CPU 就能完成相同的工作，那么您可以在该节点上突然运行三个 pod 而不是两个，从而将集群的可伸缩性整体提高了 50%（或者将成本降低了 33%）。

# Kubernetes 的 SLO

Kubernetes 有**服务水平目标**（**SLOs**）。在尝试改进性能和可伸缩性时，必须遵守这些保证。Kubernetes 对 API 调用有一秒的响应时间。那是 1,000 毫秒。它实际上在大多数情况下实现了一个数量级的更快响应时间。

# 测量 API 的响应速度

API 有许多不同的端点。没有简单的 API 响应性数字。每个调用都必须单独测量。此外，由于系统的复杂性和分布式特性，更不用说网络问题，结果可能会有很大的波动。一个可靠的方法是将 API 测量分成单独的端点，然后随着时间的推移进行大量测试，并查看百分位数（这是标准做法）。

使用足够的硬件来管理大量对象也很重要。Kubernetes 团队在这次测试中使用了一个 32 核心、120GB 的虚拟机作为主节点。

下图描述了 Kubernetes 1.3 各种重要 API 调用延迟的 50th、90th 和 99th 百分位数。你可以看到，90th 百分位数非常低，低于 20 毫秒。甚至对于`DELETE` pods 操作，99th 百分位数也低于 125 毫秒，对于其他所有操作也低于 100 毫秒：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-k8s/img/ebd83246-25cd-4544-9354-0137881e81e3.jpg)

另一类 API 调用是 LIST 操作。这些调用更加昂贵，因为它们需要在大型集群中收集大量信息，组成响应，并发送可能很大的响应。这就是性能改进，比如内存读取缓存和协议缓冲区序列化真正发挥作用的地方。响应时间理所当然地大于单个 API 调用，但仍远低于一秒（1000 毫秒）的 SLO。

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-k8s/img/8dbffc43-0ad7-4818-9d70-18f9b77b6f24.jpg)

这很好，但是看看 Kubernetes 1.6 在一个 5000 个节点的集群上的 API 调用延迟：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-k8s/img/a2a907bc-9ab2-4c00-9ecf-f6d7a1135793.png)

# 衡量端到端的 Pod 启动时间

大型动态集群最重要的性能特征之一是端到端的 Pod 启动时间。Kubernetes 一直在创建、销毁和调度 Pod。可以说，Kubernetes 的主要功能是调度 Pod。

在下图中，您可以看到 Pod 启动时间比 API 调用不太波动。这是有道理的，因为有很多工作需要做，比如启动一个不依赖于集群大小的运行时的新实例。在拥有 1,000 个节点的 Kubernetes 1.2 上，启动 Pod 的 99th 百分位端到端时间不到 3 秒。在 Kubernetes 1.3 上，启动 Pod 的 99th 百分位端到端时间略高于 2.5 秒。值得注意的是，时间非常接近，但在拥有 2,000 个节点的 Kubernetes 1.3 上，比拥有 1,000 个节点的集群稍微好一点：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-k8s/img/13d475e6-8cf8-4e11-ac2f-e81dd4a16300.jpg)

Kubernetes 1.6 将其提升到了下一个级别，并在更大的集群上表现得更好：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-k8s/img/ef3e1fed-94c5-41e5-8e4a-fbe72aa0a21f.png)

# 在规模上测试 Kubernetes

拥有数千个节点的集群是昂贵的。即使像 Kubernetes 这样得到 Google 和其他行业巨头支持的项目，仍然需要找到合理的测试方法，而不会让自己破产。

Kubernetes 团队每次发布都会在真实集群上运行全面的测试，以收集真实世界的性能和可伸缩性数据。然而，还需要一种轻量级和更便宜的方法来尝试潜在的改进，并检测回归。这就是 Kubemark。

# 介绍 Kubemark 工具

Kubemark 是一个运行模拟节点（称为空心节点）的 Kubernetes 集群，用于针对大规模（空心）集群运行轻量级基准测试。一些在真实节点上可用的 Kubernetes 组件，如 kubelet，被替换为空心 kubelet。空心 kubelet 模拟了真实 kubelet 的许多功能。空心 kubelet 实际上不会启动任何容器，也不会挂载任何卷。但从 Kubernetes 集群的角度来看 - 存储在 etcd 中的状态 - 所有这些对象都存在，您可以查询 API 服务器。空心 kubelet 实际上是带有注入的模拟 Docker 客户端的真实 kubelet，该客户端不执行任何操作。

另一个重要的空心组件是`hollow-proxy`，它模拟了 Kubeproxy 组件。它再次使用真实的 Kubeproxy 代码，具有一个不执行任何操作并避免触及 iptables 的模拟 proxier 接口。

# 设置 Kubemark 集群

Kubemark 集群利用了 Kubernetes 的强大功能。要设置 Kubemark 集群，请执行以下步骤：

1.  创建一个常规的 Kubernetes 集群，我们可以在其中运行`N hollow-nodes`。

1.  创建一个专用的 VM 来启动 Kubemark 集群的所有主要组件。

1.  在基本 Kubernetes 集群上安排`N 个空节点` pods。这些空节点被配置为与运行在专用 VM 上的 Kubemark API 服务器进行通信。

1.  通过在基本集群上安排并配置它们与 Kubemark API 服务器进行通信来创建附加的 pods。

GCP 上提供了完整的指南，网址为[`bit.ly/2nPMkwc`](http://bit.ly/2nPMkwc)。

# 将 Kubemark 集群与真实世界集群进行比较

Kubemark 集群的性能与真实集群的性能非常相似。对于 pod 启动的端到端延迟，差异可以忽略不计。对于 API 的响应性，差异较大，尽管通常不到两倍。然而，趋势完全相同：真实集群中的改进/退化在 Kubemark 中表现为类似百分比的下降/增加。

# 总结

在本章中，我们涵盖了许多与扩展 Kubernetes 集群相关的主题。我们讨论了水平 pod 自动缩放器如何根据 CPU 利用率或其他指标自动管理运行的 pod 数量，如何在自动缩放的情况下正确安全地执行滚动更新，以及如何通过资源配额处理稀缺资源。然后，我们转向了整体容量规划和管理集群的物理或虚拟资源。最后，我们深入探讨了将单个 Kubernetes 集群扩展到处理 5,000 个节点的真实示例。

到目前为止，您已经对 Kubernetes 集群面对动态和不断增长的工作负载时涉及的所有因素有了很好的理解。您有多种工具可供选择，用于规划和设计自己的扩展策略。

在下一章中，我们将深入探讨高级 Kubernetes 网络。Kubernetes 具有基于**通用网络接口**（**CNI**）的网络模型，并支持多个提供程序。


# 第十章：高级 Kubernetes 网络

在本章中，我们将研究网络这一重要主题。作为一个编排平台，Kubernetes 管理在不同机器（物理或虚拟）上运行的容器/Pod，并需要一个明确的网络模型。我们将讨论以下主题：

+   Kubernetes 网络模型

+   Kubernetes 支持的标准接口，如 EXEC、Kubenet，特别是 CNI

+   满足 Kubernetes 网络要求的各种网络解决方案

+   网络策略和负载均衡选项

+   编写自定义 CNI 插件

在本章结束时，您将了解 Kubernetes 对网络的处理方式，并熟悉标准接口、网络实现和负载均衡等方面的解决方案空间。甚至可以自己编写自己的 CNI 插件。

# 理解 Kubernetes 网络模型

Kubernetes 网络模型基于一个扁平的地址空间。集群中的所有 Pod 都可以直接相互通信。每个 Pod 都有自己的 IP 地址。无需配置任何 NAT。此外，同一 Pod 中的容器共享其 Pod 的 IP 地址，并且可以通过 localhost 相互通信。这个模型非常有见地，一旦设置好，就会极大地简化开发人员和管理员的生活。它特别容易将传统网络应用迁移到 Kubernetes。一个 Pod 代表一个传统节点，每个容器代表一个传统进程。

# Pod 内通信（容器到容器）

运行中的 Pod 始终被调度到一个（物理或虚拟）节点上。这意味着所有的容器都在同一个节点上运行，并且可以以各种方式相互通信，比如本地文件系统、任何 IPC 机制，或者使用 localhost 和众所周知的端口。不同的 Pod 之间不会发生端口冲突，因为每个 Pod 都有自己的 IP 地址，当 Pod 中的容器使用 localhost 时，它只适用于 Pod 的 IP 地址。因此，如果 Pod 1 中的容器 1 连接到 Pod 1 上的端口`1234`，而 Pod 1 上的容器 2 监听该端口，它不会与同一节点上运行的 Pod 2 中的另一个容器监听的端口`1234`发生冲突。唯一需要注意的是，如果要将端口暴露给主机，那么应该注意 Pod 到节点的亲和性。这可以通过多种机制来处理，比如 DaemonSet 和 Pod 反亲和性。

# Pod 间通信（Pod 到 Pod）

在 Kubernetes 中，Pod 被分配了一个网络可见的 IP 地址（不是私有的节点）。Pod 可以直接通信，无需网络地址转换、隧道、代理或任何其他混淆层的帮助。可以使用众所周知的端口号来进行无需配置的通信方案。Pod 的内部 IP 地址与其他 Pod 看到的外部 IP 地址相同（在集群网络内；不暴露给外部世界）。这意味着标准的命名和发现机制，如 DNS，可以直接使用。

# Pod 与服务之间的通信

Pod 可以使用它们的 IP 地址和众所周知的端口直接相互通信，但这需要 Pod 知道彼此的 IP 地址。在 Kubernetes 集群中，Pod 可能会不断被销毁和创建。服务提供了一个非常有用的间接层，因为即使实际响应请求的 Pod 集合不断变化，服务也是稳定的。此外，您会获得自动的高可用负载均衡，因为每个节点上的 Kube-proxy 负责将流量重定向到正确的 Pod：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-k8s/img/640c8105-160e-4829-80a6-2c1381eddd02.png)

# 外部访问

最终，一些容器需要从外部世界访问。Pod IP 地址在外部不可见。服务是正确的载体，但外部访问通常需要两次重定向。例如，云服务提供商负载均衡器是 Kubernetes 感知的，因此它不能直接将流量定向到运行可以处理请求的 Pod 的节点。相反，公共负载均衡器只是将流量定向到集群中的任何节点，该节点上的 Kube-proxy 将再次重定向到适当的 Pod，如果当前节点不运行必要的 Pod。

下图显示了右侧的外部负载均衡器所做的一切只是将流量发送到达到代理的所有节点，代理负责进一步路由，如果需要的话。

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-k8s/img/44ed300f-4643-4e4c-93c5-db61ee64e1c7.png)

# Kubernetes 网络与 Docker 网络的对比

Docker 网络遵循不同的模型，尽管随着时间的推移，它已经趋向于 Kubernetes 模型。在 Docker 网络中，每个容器都有自己的私有 IP 地址，来自`172.xxx.xxx.xxx`地址空间，限定在自己的节点上。它可以通过它们自己的`172.xxx.xxx.xxx` IP 地址与同一节点上的其他容器进行通信。这对 Docker 来说是有意义的，因为它没有多个交互容器的 pod 的概念，所以它将每个容器建模为一个具有自己网络身份的轻量级 VM。请注意，使用 Kubernetes，运行在同一节点上的不同 pod 的容器不能通过 localhost 连接（除非暴露主机端口，这是不鼓励的）。整个想法是，一般来说，Kubernetes 可以在任何地方杀死和创建 pod，因此不同的 pod 一般不应该依赖于节点上可用的其他 pod。守护进程集是一个值得注意的例外，但 Kubernetes 网络模型旨在适用于所有用例，并且不为同一节点上不同 pod 之间的直接通信添加特殊情况。

Docker 容器如何跨节点通信？容器必须将端口发布到主机。这显然需要端口协调，因为如果两个容器尝试发布相同的主机端口，它们将互相冲突。然后容器（或其他进程）连接到被通道化到容器中的主机端口。一个很大的缺点是，容器无法自我注册到外部服务，因为它们不知道它们所在主机的 IP 地址。您可以通过在运行容器时将主机的 IP 地址作为环境变量传递来解决这个问题，但这需要外部协调并且使过程复杂化。

以下图表显示了 Docker 的网络设置。每个容器都有自己的 IP 地址；Docker 在每个节点上创建了`docker0`桥接：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-k8s/img/f8e87edb-e287-404f-a56b-4bcee0767eed.png)

# 查找和发现

为了使 pod 和容器能够相互通信，它们需要找到彼此。容器定位其他容器或宣布自己有几种方法。还有一些架构模式允许容器间间接交互。每种方法都有其优缺点。

# 自注册

我们已经多次提到自注册。让我们确切地理解它的含义。当一个容器运行时，它知道其 pod 的 IP 地址。每个希望对集群中的其他容器可访问的容器都可以连接到某个注册服务并注册其 IP 地址和端口。其他容器可以查询注册服务以获取所有已注册容器的 IP 地址和端口，并连接到它们。当一个容器被销毁（正常情况下），它将取消注册。如果一个容器非正常死亡，那么需要建立一些机制来检测。例如，注册服务可以定期 ping 所有已注册的容器，或者要求容器定期向注册服务发送保持活动的消息。

自注册的好处在于一旦通用注册服务就位（无需为不同目的定制），就无需担心跟踪容器。另一个巨大的好处是，容器可以采用复杂的策略，并决定在本地条件下暂时取消注册，比如如果一个容器很忙，不想在这一刻接收更多请求。这种智能和分散的动态负载平衡在全球范围内很难实现。缺点是注册服务是另一个非标准组件，容器需要了解它以便定位其他容器。

# 服务和端点

Kubernetes 服务可以被视为注册服务。属于服务的 pod 会根据其标签自动注册。其他 pod 可以查找端点以找到所有服务 pod，或者利用服务本身直接发送消息到服务，消息将被路由到其中一个后端 pod。尽管大多数情况下，pod 将消息直接发送到服务本身，由服务转发到其中一个后端 pod。

# 与队列松散耦合的连接

如果容器可以相互通信，而不知道它们的 IP 地址和端口，甚至不知道服务 IP 地址或网络名称呢？如果大部分通信可以是异步和解耦的呢？在许多情况下，系统可以由松散耦合的组件组成，这些组件不仅不知道其他组件的身份，甚至不知道其他组件的存在。队列有助于这种松散耦合的系统。组件（容器）监听来自队列的消息，响应消息，执行它们的工作，并在队列中发布有关进度、完成状态和错误的消息。队列有许多好处：

+   无需协调即可添加处理能力；只需添加更多监听队列的容器

+   通过队列深度轻松跟踪整体负载

+   通过对消息和/或主题进行版本控制，轻松同时运行多个组件的不同版本

+   通过使多个消费者以不同模式处理请求，轻松实现负载均衡以及冗余

队列的缺点包括：

+   需要确保队列提供适当的耐用性和高可用性，以免成为关键的单点故障。

+   容器需要使用异步队列 API（可以抽象化）

+   实现请求-响应需要在响应队列上进行有些繁琐的监听

总的来说，队列是大规模系统的一个很好的机制，可以在大型 Kubernetes 集群中使用，以简化协调工作。

# 与数据存储松散耦合的连接

另一种松散耦合的方法是使用数据存储（例如 Redis）存储消息，然后其他容器可以读取它们。虽然可能，但这不是数据存储的设计目标，结果通常是繁琐、脆弱，并且性能不佳。数据存储针对数据存储进行了优化，而不是用于通信。也就是说，数据存储可以与队列一起使用，其中一个组件将一些数据存储在数据存储中，然后发送一条消息到队列，表示数据已准备好进行处理。多个组件监听该消息，并且都开始并行处理数据。

# Kubernetes 入口

Kubernetes 提供了一个入口资源和控制器，旨在将 Kubernetes 服务暴露给外部世界。当然，您也可以自己做，但定义入口所涉及的许多任务在特定类型的入口（如 Web 应用程序、CDN 或 DDoS 保护器）的大多数应用程序中是常见的。您还可以编写自己的入口对象。

“入口”对象通常用于智能负载平衡和 TLS 终止。您可以从内置入口中受益，而不是配置和部署自己的 NGINX 服务器。如果您需要复习，请转到第六章，*使用关键的 Kubernetes 资源*，在那里我们讨论了带有示例的入口资源。

# Kubernetes 网络插件

Kubernetes 具有网络插件系统，因为网络如此多样化，不同的人希望以不同的方式实现它。Kubernetes 足够灵活，可以支持任何场景。主要的网络插件是 CNI，我们将深入讨论。但 Kubernetes 还配备了一个更简单的网络插件，称为 Kubenet。在我们详细讨论之前，让我们就 Linux 网络的基础知识达成一致（只是冰山一角）。

# 基本的 Linux 网络

默认情况下，Linux 具有单个共享网络空间。物理网络接口都可以在此命名空间中访问，但物理命名空间可以分成多个逻辑命名空间，这与容器网络非常相关。

# IP 地址和端口

网络实体通过其 IP 地址进行标识。服务器可以在多个端口上监听传入连接。客户端可以连接（TCP）或向其网络内的服务器发送数据（UDP）。

# 网络命名空间

命名空间将一堆网络设备分组在一起，以便它们可以在同一命名空间中到达其他服务器，但即使它们在物理上位于同一网络上，也不能到达其他服务器。通过桥接、交换机、网关和路由可以连接网络或网络段。

# 子网、网络掩码和 CIDR

在设计和维护网络时，网络段的细分非常有用。将网络划分为具有共同前缀的较小子网是一种常见做法。这些子网可以由表示子网大小（可以包含多少主机）的位掩码来定义。例如，`255.255.255.0`的子网掩码意味着前三个八位字节用于路由，只有 256（实际上是 254）个单独的主机可用。无类别域间路由（CIDR）表示法经常用于此目的，因为它更简洁，编码更多信息，并且还允许将来自多个传统类别（A、B、C、D、E）的主机组合在一起。例如，`172.27.15.0/24`表示前 24 位（三个八位字节）用于路由。

# 虚拟以太网设备

**虚拟以太网**（**veth**）设备代表物理网络设备。当您创建一个与物理设备连接的`veth`时，您可以将该`veth`（以及物理设备）分配到一个命名空间中，其他命名空间的设备无法直接访问它，即使它们在物理上位于同一个本地网络上。

# 桥接器

桥接器将多个网络段连接到一个聚合网络，以便所有节点可以彼此通信。桥接是在 OSI 网络模型的 L1（物理）和 L2（数据链路）层进行的。

# 路由

路由连接不同的网络，通常基于路由表，指示网络设备如何将数据包转发到其目的地。路由是通过各种网络设备进行的，如路由器、桥接器、网关、交换机和防火墙，包括常规的 Linux 框。

# 最大传输单元

**最大传输单元**（**MTU**）确定数据包的大小限制。例如，在以太网网络上，MTU 为 1500 字节。MTU 越大，有效载荷和标头之间的比率就越好，这是一件好事。缺点是最小延迟减少，因为您必须等待整个数据包到达，而且如果出现故障，您必须重新传输整个数据包。

# Pod 网络

以下是一个描述通过`veth0`在网络层面上描述 pod、主机和全局互联网之间关系的图表：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-k8s/img/5cf26bd3-81f9-42df-b4ad-f004f50d5e6d.png)

# Kubenet

回到 Kubernetes。Kubenet 是一个网络插件；它非常基础，只是创建一个名为`cbr0`的 Linux 桥接和为每个 pod 创建一个`veth`。云服务提供商通常使用它来设置节点之间的通信路由规则，或者在单节点环境中使用。`veth`对将每个 pod 连接到其主机节点，使用来自主机 IP 地址范围的 IP 地址。

# 要求

Kubenet 插件有以下要求：

+   必须为节点分配一个子网，以为其 pod 分配 IP 地址

+   版本 0.2.0 或更高版本需要标准的 CNI 桥接、`lo`和 host-local 插件

+   Kubelet 必须使用`--network-plugin=kubenet`参数运行

+   Kubelet 必须使用`--non-masquerade-cidr=<clusterCidr>`参数运行

# 设置 MTU

MTU 对于网络性能至关重要。Kubernetes 网络插件（如 Kubenet）会尽最大努力推断最佳 MTU，但有时它们需要帮助。如果现有的网络接口（例如 Docker 的`docker0`桥接）设置了较小的 MTU，则 Kubenet 将重用它。另一个例子是 IPSEC，由于 IPSEC 封装开销增加，需要降低 MTU，但 Kubenet 网络插件没有考虑到这一点。解决方案是避免依赖 MTU 的自动计算，只需通过`--network-plugin-mtu`命令行开关告诉 Kubelet 应该为网络插件使用什么 MTU，这个开关提供给所有网络插件。然而，目前只有 Kubenet 网络插件考虑了这个命令行开关。

# 容器网络接口（CNI）

CNI 既是一个规范，也是一组用于编写网络插件以配置 Linux 容器中的网络接口的库（不仅仅是 Docker）。该规范实际上是从 rkt 网络提案演变而来的。CNI 背后有很多动力，正在快速成为行业标准。一些使用 CNI 的组织有：

+   Kubernetes

+   Kurma

+   云原生

+   Nuage

+   红帽

+   Mesos

CNI 团队维护一些核心插件，但也有很多第三方插件对 CNI 的成功做出了贡献：

+   **Project Calico**：三层虚拟网络

+   **Weave**：多主机 Docker 网络

+   **Contiv 网络**：基于策略的网络

+   **Cilium**：用于容器的 BPF 和 XDP

+   **Multus**：一个多插件

+   **CNI-Genie**：通用 CNI 网络插件

+   **Flannel**：为 Kubernetes 设计的容器网络布局

+   **Infoblox**：企业级容器 IP 地址管理

# 容器运行时

CNI 为网络应用容器定义了插件规范，但插件必须插入提供一些服务的容器运行时中。在 CNI 的上下文中，应用容器是一个可寻址的网络实体（具有自己的 IP 地址）。对于 Docker，每个容器都有自己的 IP 地址。对于 Kubernetes，每个 pod 都有自己的 IP 地址，而 pod 是 CNI 容器，而不是 pod 内的容器。

同样，rkt 的应用容器类似于 Kubernetes 中的 pod，因为它们可能包含多个 Linux 容器。如果有疑问，只需记住 CNI 容器必须有自己的 IP 地址。运行时的工作是配置网络，然后执行一个或多个 CNI 插件，以 JSON 格式将网络配置传递给它们。

以下图表显示了一个容器运行时使用 CNI 插件接口与多个 CNI 插件进行通信：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-k8s/img/9298924f-10d1-4fdc-b16f-749c5674e1b2.png)

# CNI 插件

CNI 插件的工作是将网络接口添加到容器网络命名空间，并通过`veth`对将容器桥接到主机。然后，它应通过 IPAM（IP 地址管理）插件分配 IP 地址并设置路由。

容器运行时（Docker，rkt 或任何其他符合 CRI 标准的运行时）将 CNI 插件作为可执行文件调用。插件需要支持以下操作：

+   将容器添加到网络

+   从网络中删除容器

+   报告版本

插件使用简单的命令行界面，标准输入/输出和环境变量。以 JSON 格式的网络配置通过标准输入传递给插件。其他参数被定义为环境变量：

+   `CNI_COMMAND`：指示所需操作的命令；`ADD`，`DEL`或`VERSION`。

+   `CNI_CONTAINERID`：容器 ID。

+   `CNI_NETNS`：网络命名空间文件的路径。

+   `*` `CNI_IFNAME`：要设置的接口名称；插件必须遵守此接口名称或返回一个`error`。

+   `*` `CNI_ARGS`：用户在调用时传入的额外参数。字母数字键值对由分号分隔，例如，`FOO=BAR;ABC=123`。

+   `CNI_PATH`：要搜索 CNI 插件可执行文件的路径列表。路径由操作系统特定的列表分隔符分隔，例如，在 Linux 上是`:`，在 Windows 上是`；`。

如果命令成功，插件将返回零退出代码，并且生成的接口（在`ADD`命令的情况下）将作为 JSON 流式传输到标准输出。这种低技术接口很聪明，因为它不需要任何特定的编程语言、组件技术或二进制 API。CNI 插件编写者也可以使用他们喜欢的编程语言。

使用`ADD`命令调用 CNI 插件的结果如下：

```
{
 "cniVersion": "0.3.0",
 "interfaces": [ (this key omitted by IPAM plugins)
 {
 "name": "<name>",
 "mac": "<MAC address>", (required if L2 addresses are meaningful)
 "sandbox": "<netns path or hypervisor identifier>" (required for container/hypervisor interfaces, empty/omitted for host interfaces)
 }
 ],
 "ip": [
 {
 "version": "<4-or-6>",
 "address": "<ip-and-prefix-in-CIDR>",
 "gateway": "<ip-address-of-the-gateway>", (optional)
 "interface": <numeric index into 'interfaces' list>
 },
 ...
 ],
 "routes": [ (optional)
 {
 "dst": "<ip-and-prefix-in-cidr>",
 "gw": "<ip-of-next-hop>" (optional)
 },
 ...
 ]
 "dns": {
 "nameservers": <list-of-nameservers> (optional)
 "domain": <name-of-local-domain> (optional)
 "search": <list-of-additional-search-domains> (optional)
 "options": <list-of-options> (optional)
 }
}
```

输入网络配置包含大量信息：`cniVersion`、名称、类型、`args`（可选）、`ipMasq`（可选）、`ipam`和`dns`。`ipam`和`dns`参数是具有自己指定键的字典。以下是网络配置的示例：

```
{
 "cniVersion": "0.3.0",
 "name": "dbnet",
 "type": "bridge",
 // type (plugin) specific
 "bridge": "cni0",
 "ipam": {
 "type": "host-local",
 // ipam specific
 "subnet": "10.1.0.0/16",
 "gateway": "10.1.0.1"
 },
 "dns": {
 "nameservers": [ "10.1.0.1" ]
 }
}  
```

请注意，可以添加额外的特定于插件的元素。在这种情况下，`bridge: cni0`元素是特定的`bridge`插件理解的自定义元素。

`CNI 规范`还支持网络配置列表，其中可以按顺序调用多个 CNI 插件。稍后，我们将深入研究一个完全成熟的 CNI 插件实现。

# Kubernetes 网络解决方案

网络是一个广阔的话题。有许多设置网络和连接设备、pod 和容器的方法。Kubernetes 对此不能有意见。对于 pod 的高级网络模型是 Kubernetes 规定的。在这个空间内，有许多有效的解决方案是可能的，具有不同环境的各种功能和策略。在本节中，我们将研究一些可用的解决方案，并了解它们如何映射到 Kubernetes 网络模型。

# 裸金属集群上的桥接

最基本的环境是一个只有 L2 物理网络的原始裸金属集群。您可以使用 Linux 桥设备将容器连接到物理网络。该过程非常复杂，需要熟悉低级 Linux 网络命令，如`brctl`、`ip addr`、`ip route`、`ip link`、`nsenter`等。如果您打算实施它，这篇指南可以作为一个很好的起点（搜索*使用 Linux 桥设备*部分）：[`blog.oddbit.com/2014/08/11/four-ways-to-connect-a-docker/`](http://blog.oddbit.com/2014/08/11/four-ways-to-connect-a-docker/)。

# Contiv

Contiv 是一个通用的容器网络插件，可以直接与 Docker、Mesos、Docker Swarm 以及当然 Kubernetes 一起使用，通过一个 CNI 插件。Contiv 专注于与 Kubernetes 自身网络策略对象有些重叠的网络策略。以下是 Contiv net 插件的一些功能：

+   支持 libnetwork 的 CNM 和 CNI 规范

+   功能丰富的策略模型，提供安全、可预测的应用部署

+   用于容器工作负载的最佳吞吐量

+   多租户、隔离和重叠子网

+   集成 IPAM 和服务发现

+   各种物理拓扑：

+   Layer2（VLAN）

+   Layer3（BGP）

+   覆盖（VXLAN）

+   思科 SDN 解决方案（ACI）

+   IPv6 支持

+   可扩展的策略和路由分发

+   与应用蓝图的集成，包括以下内容：

+   Docker-compose

+   Kubernetes 部署管理器

+   服务负载平衡内置东西向微服务负载平衡

+   用于存储、控制（例如，`etcd`/`consul`）、网络和管理流量的流量隔离

+   Contiv 具有许多功能和能力。由于其广泛的适用范围以及它适用于多个平台，我不确定它是否是 Kubernetes 的最佳选择。

# Open vSwitch

Open vSwitch 是一个成熟的基于软件的虚拟交换解决方案，得到许多大公司的认可。**Open Virtualization Network**（**OVN**）解决方案可以让您构建各种虚拟网络拓扑。它有一个专门的 Kubernetes 插件，但设置起来并不简单，正如这个指南所示：[`github.com/openvswitch/ovn-kubernetes`](https://github.com/openvswitch/ovn-kubernetes)。Linen CNI 插件可能更容易设置，尽管它不支持 OVN 的所有功能：[`github.com/John-Lin/linen-cni`](https://github.com/John-Lin/linen-cni)。这是 Linen CNI 插件的图表：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-k8s/img/24da1447-6f6c-4ab2-90a3-38cd607be551.png)

Open vSwitch 可以连接裸机服务器、虚拟机和 pod/容器，使用相同的逻辑网络。它实际上支持覆盖和底层模式。

以下是一些其关键特性：

+   标准的 802.1Q VLAN 模型，带有干线和接入端口

+   上游交换机上带或不带 LACP 的 NIC 绑定

+   NetFlow、sFlow(R)和镜像，以增加可见性

+   QoS（服务质量）配置，以及流量控制

+   Geneve、GRE、VXLAN、STT 和 LISP 隧道

+   802.1ag 连接故障管理

+   OpenFlow 1.0 加上许多扩展

+   具有 C 和 Python 绑定的事务配置数据库

+   使用 Linux 内核模块进行高性能转发

# Nuage 网络 VCS

Nuage 网络的**虚拟化云服务**（**VCS**）产品提供了一个高度可扩展的基于策略的**软件定义网络**（**SDN**）平台。这是一个建立在开源 Open vSwitch 数据平面之上的企业级产品，配备了基于开放标准构建的功能丰富的 SDN 控制器。

Nuage 平台使用覆盖层在 Kubernetes Pods 和非 Kubernetes 环境（VM 和裸金属服务器）之间提供无缝的基于策略的网络。Nuage 的策略抽象模型是针对应用程序设计的，使得声明应用程序的细粒度策略变得容易。该平台的实时分析引擎实现了对 Kubernetes 应用程序的可见性和安全监控。

此外，所有 VCS 组件都可以安装在容器中。没有特殊的硬件要求。

# Canal

Canal 是两个开源项目的混合体：Calico 和 Flannel。**Canal**这个名字是这两个项目名称的混成词。由 CoreOS 开发的 Flannel 专注于容器网络，**Calico**专注于网络策略。最初，它们是独立开发的，但用户希望将它们一起使用。目前，开源的 Canal 项目是一个部署模式，可以将这两个项目作为独立的 CNI 插件进行安装。由 Calico 创始人组建的 Tigera 现在正在引导这两个项目，并计划更紧密地集成，但自从他们发布了用于 Kubernetes 的安全应用连接解决方案后，重点似乎转向了为 Flannel 和 Calico 做出贡献，以简化配置和集成，而不是提供统一的解决方案。以下图表展示了 Canal 的当前状态以及它与 Kubernetes 和 Mesos 等容器编排器的关系：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-k8s/img/4e064c65-c47a-4e1f-ab9a-52c758784c94.png)

请注意，与 Kubernetes 集成时，Canal 不再直接使用`etcd`，而是依赖于 Kubernetes API 服务器。

# 法兰绒

Flannel 是一个虚拟网络，为每个主机提供一个子网，用于容器运行时。它在每个主机上运行一个`flaneld`代理，该代理从存储在`etcd`中的保留地址空间中为节点分配子网。容器之间以及最终主机之间的数据包转发由多个后端之一完成。最常见的后端使用默认情况下通过端口`8285`进行的 TUN 设备上的 UDP 进行隧道传输（确保防火墙中已打开）。

以下图表详细描述了 Flannel 的各个组件、它创建的虚拟网络设备以及它们如何通过`docker0`桥与主机和 pod 进行交互。它还显示了数据包的 UDP 封装以及它们在主机之间的传输：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-k8s/img/a1fc953d-4572-4b46-a1b4-231d0251b7ca.png)

其他后端包括以下内容：

+   `vxlan`：使用内核 VXLAN 封装数据包。

+   `host-gw`：通过远程机器 IP 创建到子网的 IP 路由。请注意，这需要在运行 Flannel 的主机之间直接的二层连接。

+   `aws-vpc`：在 Amazon VPC 路由表中创建 IP 路由。

+   `gce`：在 Google 计算引擎网络中创建 IP 路由。

+   `alloc`：仅执行子网分配（不转发数据包）。

+   `ali-vpc`：在阿里云 VPC 路由表中创建 IP 路由。

# Calico 项目

Calico 是一个多功能的容器虚拟网络和网络安全解决方案。Calico 可以与所有主要的容器编排框架集成

和运行时：

+   Kubernetes（CNI 插件）

+   Mesos（CNI 插件）

+   Docker（libnework 插件）

+   OpenStack（Neutron 插件）

Calico 还可以在本地部署或在公共云上部署，具有完整的功能集。Calico 的网络策略执行可以针对每个工作负载进行专门化，并确保流量被精确控制，数据包始终从其源头到经过审查的目的地。Calico 可以自动将编排平台的网络策略概念映射到自己的网络策略。Kubernetes 网络策略的参考实现是 Calico。

# Romana

Romana 是一个现代的云原生容器网络解决方案。它在第 3 层操作，利用标准 IP 地址管理技术。整个网络可以成为隔离单元，因为 Romana 使用 Linux 主机创建网关和网络的路由。在第 3 层操作意味着不需要封装。网络策略作为分布式防火墙在所有端点和服务上执行。跨云平台和本地部署的混合部署更容易，因为无需配置虚拟覆盖网络。

新的 Romana 虚拟 IP 允许本地用户通过外部 IP 和服务规范在第 2 层 LAN 上公开服务。

Romana 声称他们的方法带来了显著的性能改进。以下图表显示了 Romana 如何消除与 VXLAN 封装相关的大量开销。

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-k8s/img/8688357c-538c-4144-be52-aee50bb2e67c.png)

# Weave 网络

Weave 网络主要关注易用性和零配置。它在底层使用 VXLAN 封装和每个节点上的微型 DNS。作为开发人员，您在高抽象级别上操作。您为容器命名，Weave 网络让您连接并使用标准端口进行服务。这有助于您将现有应用程序迁移到容器化应用程序和微服务中。Weave 网络具有用于与 Kubernetes（和 Mesos）接口的 CNI 插件。在 Kubernetes 1.4 及更高版本上，您可以通过运行一个部署 DaemonSet 的单个命令将 Weave 网络集成到 Kubernetes 中。

```
kubectl apply -f https://git.io/weave-kube 
```

每个节点上的 Weave 网络 pod 将负责将您创建的任何新 pod 连接到 Weave 网络。Weave 网络支持网络策略 API，提供了一个完整而易于设置的解决方案。

# 有效使用网络策略

Kubernetes 网络策略是关于管理流向选定的 pod 和命名空间的网络流量。在部署和编排了数百个微服务的世界中，通常情况下是 Kubernetes，管理 pod 之间的网络和连接至关重要。重要的是要理解，它并不是主要的安全机制。如果攻击者可以访问内部网络，他们可能能够创建符合现有网络策略并与其他 pod 自由通信的自己的 pod。在前一节中，我们看了不同的 Kubernetes 网络解决方案，并侧重于容器网络接口。在本节中，重点是网络策略，尽管网络解决方案与如何在其之上实现网络策略之间存在着紧密的联系。

# 了解 Kubernetes 网络策略设计

网络策略是选择的 pod 之间以及其他网络端点之间如何通信的规范。`NetworkPolicy`资源使用标签选择 pod，并定义白名单规则，允许流量到达选定的 pod，除了给定命名空间的隔离策略允许的流量之外。

# 网络策略和 CNI 插件

网络策略和 CNI 插件之间存在复杂的关系。一些 CNI 插件同时实现了网络连接和网络策略，而其他一些只实现了其中一个方面，但它们可以与另一个实现了另一个方面的 CNI 插件合作（例如，Calico 和 Flannel）。

# 配置网络策略

网络策略是通过`NetworkPolicy`资源进行配置的。以下是一个示例网络策略：

```
apiVersion: networking.k8s.io/v1kind: NetworkPolicy 
metadata: 
 name: test-network-policy 
 namespace: default 
spec: 
 podSelector: 
  matchLabels: 
    role: db 
 ingress: 
  - from: 
     - namespaceSelector: 
        matchLabels: 
         project: awesome-project 
     - podSelector: 
        matchLabels: 
         role: frontend 
    ports: 
     - protocol: tcp 
       port: 6379 
```

# 实施网络策略

虽然网络策略 API 本身是通用的，并且是 Kubernetes API 的一部分，但实现与网络解决方案紧密耦合。这意味着在每个节点上都有一个特殊的代理或守门人，执行以下操作：

+   拦截进入节点的所有流量

+   验证其是否符合网络策略

+   转发或拒绝每个请求

Kubernetes 提供了通过 API 定义和存储网络策略的功能。执行网络策略由网络解决方案或与特定网络解决方案紧密集成的专用网络策略解决方案来完成。Calico 和 Canal 是这种方法的很好的例子。Calico 有自己的网络解决方案和网络策略解决方案，它们可以一起工作，但也可以作为 Canal 的一部分在 Flannel 之上提供网络策略执行。在这两种情况下，这两个部分之间有紧密的集成。以下图表显示了 Kubernetes 策略控制器如何管理网络策略以及节点上的代理如何执行它：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-k8s/img/fe40a1b6-1aa2-4d01-9d93-eebb58eb6d8e.png)

# 负载均衡选项

负载均衡是动态系统中的关键能力，比如 Kubernetes 集群。节点、虚拟机和 Pod 会不断变化，但客户端无法跟踪哪个个体可以处理他们的请求。即使他们可以，也需要管理集群的动态映射，频繁刷新它，并处理断开连接、无响应或者慢速节点的复杂操作。负载均衡是一个经过验证和深入理解的机制，它增加了一层间接性，将内部动荡隐藏在集群外部的客户端或消费者之外。外部和内部负载均衡器都有选项。您也可以混合使用两者。混合方法有其特定的优缺点，比如性能与灵活性。

# 外部负载均衡器

外部负载均衡器是在 Kubernetes 集群之外运行的负载均衡器。必须有一个外部负载均衡器提供商，Kubernetes 可以与其交互，以配置外部负载均衡器的健康检查、防火墙规则，并获取负载均衡器的外部 IP 地址。

以下图表显示了负载均衡器（在云中）、Kubernetes API 服务器和集群节点之间的连接。外部负载均衡器有关于哪些 Pod 运行在哪些节点上的最新信息，并且可以将外部服务流量引导到正确的 Pod。

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-k8s/img/d05c30c7-b23a-45ce-a923-c55debcda637.png)

# 配置外部负载均衡器

通过服务配置文件或直接通过 Kubectl 配置外部负载均衡器。我们使用`LoadBalancer`服务类型，而不是使用`ClusterIP`服务类型，后者直接将 Kubernetes 节点公开为负载均衡器。这取决于外部负载均衡器提供程序在集群中是否已正确安装和配置。Google 的 GKE 是最经过充分测试的提供程序，但其他云平台在其云负载均衡器之上提供了集成解决方案。

# 通过配置文件

以下是一个实现此目标的示例服务配置文件：

```
{ 
      "kind": "Service", 
      "apiVersion": "v1", 
      "metadata": { 
        "name": "example-service" 
      }, 
      "spec": { 
        "ports": [{ 
          "port": 8765, 
          "targetPort": 9376 
        }], 
        "selector": { 
          "app": "example" 
        }, 
        "type": "LoadBalancer" 
      } 
} 
```

# 通过 Kubectl

您还可以使用直接的`kubectl`命令来实现相同的结果：

```
> kubectl expose rc example --port=8765 --target-port=9376 \
--name=example-service --type=LoadBalancer  
```

使用`service`配置文件还是`kubectl`命令的决定通常取决于您设置其余基础设施和部署系统的方式。配置文件更具声明性，可以说更适合生产使用，因为您希望以一种有版本控制、可审计和可重复的方式来管理基础设施。

# 查找负载均衡器 IP 地址

负载均衡器将有两个感兴趣的 IP 地址。内部 IP 地址可在集群内部用于访问服务。集群外部的客户端将使用外部 IP 地址。为外部 IP 地址创建 DNS 条目是一个良好的做法。要获取这两个地址，请使用`kubectl describe`命令。`IP`将表示内部 IP 地址。`LoadBalancer ingress`将表示外部 IP 地址：

```
> kubectl describe services example-service
    Name:  example-service
    Selector:   app=example
    Type:     LoadBalancer
    IP:     10.67.252.103
    LoadBalancer Ingress: 123.45.678.9
    Port:     <unnamed> 80/TCP
    NodePort:   <unnamed> 32445/TCP
    Endpoints:    10.64.0.4:80,10.64.1.5:80,10.64.2.4:80
    Session Affinity: None
    No events.
```

# 保留客户端 IP 地址

有时，服务可能对客户端的源 IP 地址感兴趣。直到 Kubernetes 1.5 版本，这些信息是不可用的。在 Kubernetes 1.5 中，通过注释仅在 GKE 上可用的 beta 功能可以获取源 IP 地址。在 Kubernetes 1.7 中，API 添加了保留原始客户端 IP 的功能。

# 指定原始客户端 IP 地址保留

您需要配置服务规范的以下两个字段：

+   `service.spec.externalTrafficPolicy`：此字段确定服务是否应将外部流量路由到节点本地端点或集群范围的端点，这是默认设置。集群选项不会显示客户端源 IP，并可能将跳转到不同节点，但会很好地分散负载。本地选项保留客户端源 IP，并且只要服务类型为`LoadBalancer`或`NodePort`，就不会添加额外的跳转。其缺点是可能无法很好地平衡负载。

+   `service.spec.healthCheckNodePort`：此字段是可选的。如果使用，则服务健康检查将使用此端口号。默认值为分配节点端口。对于`LoadBalancer`类型的服务，如果其`externalTrafficPolicy`设置为`Local`，则会产生影响。

这是一个例子：

```
    {
      "kind": "Service",
      "apiVersion": "v1",
      "metadata": {
        "name": "example-service"
      },
      "spec": {
        "ports": [{
          "port": 8765,
          "targetPort": 9376
        }],
        "selector": {
          "app": "example"
        },
        "type": "LoadBalancer"
        "externalTrafficPolicy: "Local"
      }
    }  
```

# 即使在外部负载均衡中理解潜力

外部负载均衡器在节点级别运行；虽然它们将流量引导到特定的 pod，但负载分配是在节点级别完成的。这意味着如果您的服务有四个 pod，其中三个在节点 A 上，最后一个在节点 B 上，那么外部负载均衡器很可能会在节点 A 和节点 B 之间均匀分配负载。这将使节点 A 上的三个 pod 处理一半的负载（每个 1/6），而节点 B 上的单个 pod 将独自处理另一半的负载。未来可能会添加权重来解决这个问题。

# 服务负载均衡器

服务负载平衡旨在在 Kubernetes 集群内部传输内部流量，而不是用于外部负载平衡。这是通过使用`clusterIP`服务类型来实现的。可以通过使用`NodePort`服务类型直接公开服务负载均衡器，并将其用作外部负载均衡器，但它并不是为此用例而设计的。例如，诸如 SSL 终止和 HTTP 缓存之类的理想功能将不会很容易地可用。

以下图显示了服务负载均衡器（黄色云）如何将流量路由到其管理的后端 pod 之一（通过标签，当然）：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-k8s/img/6bee68dc-a3fc-4698-8b1a-07df51a7a14a.png)

# 入口

Kubernetes 中的入口在其核心是一组规则，允许入站连接到达集群服务。此外，一些入口控制器支持以下功能：

+   连接算法

+   请求限制

+   URL 重写和重定向

+   TCP/UDP 负载平衡

+   SSL 终止

+   访问控制和授权

入口是使用入口资源指定的，并由入口控制器提供服务。重要的是要注意，入口仍处于测试阶段，尚未涵盖所有必要的功能。以下是一个管理流量进入两个服务的入口资源示例。规则将外部可见的`http:// foo.bar.com/foo`映射到`s1`服务，将`http://foo.bar.com/bar`映射到`s2`服务：

```
apiVersion: extensions/v1beta1 
kind: Ingress 
metadata: 
  name: test 
spec: 
  rules: 
  - host: foo.bar.com 
    http: 
      paths: 
      - path: /foo 
        backend: 
          serviceName: s1 
          servicePort: 80 
      - path: /bar 
        backend: 
          serviceName: s2 
          servicePort: 80 
```

目前有两个官方的入口控制器。其中一个是专门为 GCE 设计的 L7 入口控制器，另一个是更通用的 NGINX 入口控制器，可以通过 ConfigMap 配置 NGINX。NGNIX 入口控制器非常复杂，并且提供了许多目前通过入口资源直接不可用的功能。它使用端点 API 直接将流量转发到 pod。它支持 Minikube、GCE、AWS、Azure 和裸机集群。有关详细审查，请查看[`github.com/kubernetes/ingress-nginx`](https://github.com/kubernetes/ingress-nginx)。

# HAProxy

我们讨论了使用云提供商外部负载均衡器，使用`LoadBalancer`服务类型以及在集群内部使用`ClusterIP`的内部服务负载均衡器。如果我们想要一个自定义的外部负载均衡器，我们可以创建一个自定义的外部负载均衡器提供程序，并使用`LoadBalancer`或使用第三种服务类型`NodePort`。**高可用性**（**HA**）代理是一个成熟且经过实战考验的负载均衡解决方案。它被认为是在本地集群中实现外部负载均衡的最佳选择。这可以通过几种方式实现：

+   利用`NodePort`并仔细管理端口分配

+   实现自定义负载均衡器提供程序接口

+   在集群内部运行 HAProxy 作为集群边缘前端服务器的唯一目标（无论是否经过负载平衡）

您可以使用所有方法与 HAProxy。不过，仍建议使用入口对象。`service-loadbalancer`项目是一个社区项目，它在 HAProxy 之上实现了一个负载均衡解决方案。您可以在[`github.com/kubernetes/contrib/tree/master/service-loadbalancer`](https://github.com/kubernetes/contrib/tree/master/service-loadbalancer)找到它。

# 利用 NodePort

每个服务将从预定义范围中分配一个专用端口。通常这是一个较高的范围，例如 30,000 及以上，以避免与使用低已知端口的其他应用程序发生冲突。在这种情况下，HAProxy 将在集群外部运行，并且将为每个服务配置正确的端口。然后它可以将任何流量转发到任何节点和 Kubernetes 通过内部服务，并且负载均衡器将其路由到适当的 pod（双重负载均衡）。当然，这是次优的，因为它引入了另一个跳跃。规避它的方法是查询 Endpoints API，并动态管理每个服务的后端 pod 列表，并直接将流量转发到 pod。

# 使用 HAProxy 自定义负载均衡器提供程序

这种方法稍微复杂一些，但好处是它与 Kubernetes 更好地集成，可以更容易地在本地和云端之间进行过渡。

# 在 Kubernetes 集群内运行 HAProxy

在这种方法中，我们在集群内部使用 HAProxy 负载均衡器。可能有多个运行 HAProxy 的节点，它们将共享相同的配置来映射传入请求并在后端服务器（以下图表中的 Apache 服务器）之间进行负载均衡。

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-k8s/img/0585274f-5df9-40ea-923b-788ba4f6168f.png)

# Keepalived VIP

Keepalived **虚拟**IP（**VIP**）并不一定是一个独立的负载均衡解决方案。它可以作为 NGINX 入口控制器或基于 HAProxy 的服务`LoadBalancer`的补充。主要动机是 Kubernetes 中的 pod 会移动，包括您的负载均衡器。这对需要稳定端点的网络外客户端造成了问题。由于性能问题，DNS 通常不够好。Keepalived 提供了一个高性能的虚拟 IP 地址，可以作为 NGINX 入口控制器或 HAProxy 负载均衡器的地址。Keepalived 利用核心 Linux 网络设施，如 IPVS（IP 虚拟服务器），并通过**虚拟冗余路由协议**（**VRRP**）实现高可用性。一切都在第 4 层（TCP/UDP）运行。配置它需要一些努力和细节的关注。幸运的是，Kubernetes 有一个`contrib`项目可以帮助您入门，网址为[`github.com/kubernetes/contrib/tree/master/keepalived-vip`](https://github.com/kubernetes/contrib/tree/master/keepalived-vip)。

# Træfic

Træfic 是一个现代的 HTTP 反向代理和负载均衡器。它旨在支持微服务。它可以与许多后端一起工作，包括 Kubernetes，以自动和动态地管理其配置。与传统的负载均衡器相比，这是一个改变游戏规则的产品。它具有令人印象深刻的功能列表：

+   它很快

+   单个 Go 可执行文件

+   微型官方 Docker 镜像

+   Rest API

+   热重新加载配置；无需重新启动进程

+   断路器，重试

+   轮询，重新平衡负载均衡器

+   指标（Rest，Prometheus，Datadog，Statsd，InfluxDB）

+   干净的 AngularJS Web UI

+   Websocket，HTTP/2，GRPC 准备就绪

+   访问日志（JSON，CLF）

+   支持 Let's Encrypt（自动 HTTPS 与更新）

+   具有集群模式的高可用性

# 编写自己的 CNI 插件

在这一部分，我们将看看实际编写自己的 CNI 插件需要什么。首先，我们将看看可能的最简单的插件——环回插件。然后，我们将检查实现大部分样板与编写 CNI 插件相关的插件框架。最后，我们将回顾桥接插件的实现。在我们深入之前，这里是一个快速提醒 CNI 插件是什么：

+   CNI 插件是可执行的

+   它负责将新容器连接到网络，为 CNI 容器分配唯一的 IP 地址，并负责路由

+   容器是一个网络命名空间（在 Kubernetes 中，一个 pod 是一个 CNI 容器）

+   网络定义以 JSON 文件的形式进行管理，但通过标准输入流传输到插件（插件不会读取任何文件）

+   辅助信息可以通过环境变量提供

# 首先看看环回插件

环回插件只是添加环回接口。它非常简单，不需要任何网络配置信息。大多数 CNI 插件都是用 Golang 实现的，环回 CNI 插件也不例外。完整的源代码可在以下链接找到：

[`github.com/containernetworking/plugins/blob/master/plugins/main/loopback`](https://github.com/containernetworking/plugins/blob/master/plugins/main/loopback)

让我们先看一下导入。来自 GitHub 上的容器网络项目的多个软件包提供了实现 CNI 插件和`netlink`软件包所需的许多构建块，用于添加和删除接口，以及设置 IP 地址和路由。我们很快将看到`skel`软件包：

```
package main
import (
  "github.com/containernetworking/cni/pkg/ns"
  "github.com/containernetworking/cni/pkg/skel"
  "github.com/containernetworking/cni/pkg/types/current"
  "github.com/containernetworking/cni/pkg/version"
  "github.com/vishvananda/netlink"
)
```

然后，插件实现了两个命令，`cmdAdd`和`cmdDel`，当`container`被添加到或从网络中移除时调用。以下是`cmdAdd`命令：

```
func cmdAdd(args *skel.CmdArgs) error { 
  args.IfName = "lo" 
  err := ns.WithNetNSPath(args.Netns, func(_ ns.NetNS) error { 
    link, err := netlink.LinkByName(args.IfName) 
    if err != nil { 
      return err // not tested 
    } 

    err = netlink.LinkSetUp(link) 
    if err != nil { 
      return err // not tested 
    } 

    return nil 
  }) 
  if err != nil { 
    return err // not tested 
  } 

  result := current.Result{} 
  return result.Print() 
} 
```

该功能的核心是将接口名称设置为`lo`（用于环回），并将链接添加到容器的网络命名空间中。`del`命令则相反：

```
func cmdDel(args *skel.CmdArgs) error { 
  args.IfName = "lo" 
  err := ns.WithNetNSPath(args.Netns, func(ns.NetNS) error { 
    link, err := netlink.LinkByName(args.IfName) 
    if err != nil { 
      return err // not tested 
    } 

    err = netlink.LinkSetDown(link) 
    if err != nil { 
      return err // not tested 
    } 

    return nil 
  }) 
  if err != nil { 
    return err // not tested 
  } 

  result := current.Result{} 
  return result.Print() 

} 
```

`main`函数只是简单地调用`skel`包，传递命令函数。`skel`包将负责运行 CNI 插件可执行文件，并在适当的时候调用`addCmd`和`delCmd`函数：

```
func main() { 
  skel.PluginMain(cmdAdd, cmdDel, version.All) 
} 
```

# 构建 CNI 插件骨架

让我们探索`skel`包，并了解其在内部的工作原理。从`PluginMain()`入口点开始，它负责调用`PluginMainWithError()`，捕获错误，将其打印到标准输出并退出：

```
func PluginMain(cmdAdd, cmdDel func(_ *CmdArgs) error, versionInfo version.PluginInfo) { 
  if e := PluginMainWithError(cmdAdd, cmdDel, versionInfo); e != nil { 
    if err := e.Print(); err != nil { 
      log.Print("Error writing error JSON to stdout: ", err) 
    } 
    os.Exit(1) 
  } 
} 
```

`PluginErrorWithMain()`实例化一个分发器，设置它与所有 I/O 流和环境，并调用其`PluginMain()`方法：

```
func PluginMainWithError(cmdAdd, cmdDel func(_ *CmdArgs) error, versionInfo version.PluginInfo) *types.Error { 
  return ( dispatcher{ 
    Getenv: os.Getenv, 
    Stdin:  os.Stdin, 
    Stdout: os.Stdout, 
    Stderr: os.Stderr, 
  }).pluginMain(cmdAdd, cmdDel, versionInfo) 
} 
```

最后，这是骨架的主要逻辑。它从环境中获取`cmd`参数（其中包括来自标准输入的配置），检测调用了哪个`cmd`，并调用适当的`plugin`函数（`cmdAdd`或`cmdDel`）。它还可以返回版本信息：

```
func (t *dispatcher) pluginMain(cmdAdd, cmdDel func(_ *CmdArgs) error, versionInfo version.PluginInfo) *types.Error { 
  cmd, cmdArgs, err := t.getCmdArgsFromEnv() 
  if err != nil { 
    return createTypedError(err.Error()) 
  } 

  switch cmd { 
  case "ADD": 
    err = t.checkVersionAndCall(cmdArgs, versionInfo, cmdAdd) 
  case "DEL": 
    err = t.checkVersionAndCall(cmdArgs, versionInfo, cmdDel) 
  case "VERSION": 
    err = versionInfo.Encode(t.Stdout) 
  default: 
    return createTypedError("unknown CNI_COMMAND: %v", cmd) 
  } 

  if err != nil { 
    if e, ok := err.(*types.Error); ok { 
      // don't wrap Error in Error 
      return e 
    } 
    return createTypedError(err.Error()) 
  } 
  return nil 
} 
```

# 审查桥接插件

桥接插件更为重要。让我们看一下其实现的一些关键部分。完整的源代码可在以下链接找到：

[`github.com/containernetworking/plugins/blob/master/plugins/main/bridge`](https://github.com/containernetworking/plugins/blob/master/plugins/main/bridge)。

它定义了一个网络配置`struct`，具有以下字段：

```
type NetConf struct { 
  types.NetConf 
  BrName                string `json:"bridge"` 
  IsGW                     bool   `json:"isGateway"` 
  IsDefaultGW         bool   `json:"isDefaultGateway"` 
  ForceAddress      bool   `json:"forceAddress"` 
  IPMasq                  bool   `json:"ipMasq"` 
  MTU                       int    `json:"mtu"` 
  HairpinMode         bool   `json:"hairpinMode"` 
  PromiscMode       bool   `json:"promiscMode"` 
} 
```

由于空间限制，我们将不会涵盖每个参数的作用以及它如何与其他参数交互。目标是理解流程，并且如果您想要实现自己的 CNI 插件，这将是一个起点。配置通过`loadNetConf()`函数从 JSON 加载。它在`cmdAdd()`和`cmdDel()`函数的开头被调用：

```
n, cniVersion, err := loadNetConf(args.StdinData) 
```

这是`cmdAdd()`函数的核心。它使用来自网络配置的信息，设置了一个`veth`，与 IPAM 插件交互以添加适当的 IP 地址，并返回结果：

```
hostInterface, containerInterface, err := setupVeth(netns, br, args.IfName, n.MTU,  
                                                                          n.HairpinMode) 
  if err != nil { 
    return err 
  } 

  // run the IPAM plugin and get back the config to apply 
  r, err := ipam.ExecAdd(n.IPAM.Type, args.StdinData) 
  if err != nil { 
    return err 
  } 

  // Convert the IPAM result was into the current Result type 
  result, err := current.NewResultFromResult(r) 
  if err != nil { 
    return err 
  } 

  if len(result.IPs) == 0 { 
    return errors.New("IPAM returned missing IP config") 
  } 

  result.Interfaces = []*current.Interface{brInterface, hostInterface, containerInterface} 
```

这只是完整实现的一部分。还有路由设置和硬件 IP 分配。我鼓励您追求完整的源代码，这是相当广泛的，以获得全貌。

# 总结

在本章中，我们涵盖了很多内容。网络是一个如此广泛的主题，有如此多的硬件、软件、操作环境和用户技能的组合，要想提出一个全面的网络解决方案，既稳健、安全、性能良好又易于维护，是一项非常复杂的工作。对于 Kubernetes 集群，云提供商大多解决了这些问题。但如果您在本地运行集群或需要定制解决方案，您有很多选择。Kubernetes 是一个非常灵活的平台，设计用于扩展。特别是网络是完全可插拔的。我们讨论的主要主题是 Kubernetes 网络模型（平面地址空间，其中 pod 可以访问其他 pod，并且在 pod 内部所有容器之间共享本地主机），查找和发现的工作原理，Kubernetes 网络插件，不同抽象级别的各种网络解决方案（许多有趣的变体），有效使用网络策略来控制集群内部的流量，负载均衡解决方案的范围，最后我们看了如何通过剖析真实实现来编写 CNI 插件。

在这一点上，您可能会感到不知所措，特别是如果您不是专家。您应该对 Kubernetes 网络的内部有很好的理解，了解实现完整解决方案所需的所有相互关联的部分，并能够根据对系统有意义的权衡来制定自己的解决方案。

在第十一章中，*在多个云和集群联合上运行 Kubernetes*，我们将更进一步，看看如何在多个集群、云提供商和联合上运行 Kubernetes。这是 Kubernetes 故事中的一个重要部分，用于地理分布式部署和最终可扩展性。联合的 Kubernetes 集群可以超越本地限制，但它们也带来了一系列挑战。


# 第十一章：在多个云上运行 Kubernetes 和集群联邦

在本章中，我们将进一步探讨在多个云上运行 Kubernetes 和集群联邦。Kubernetes 集群是一个紧密结合的单元，其中所有组件都在相对接近的地方运行，并通过快速网络（物理数据中心或云提供商可用区）连接。这对许多用例来说非常好，但有一些重要的用例需要系统扩展到超出单个集群的范围。Kubernetes 联邦是一种系统化的方法，可以将多个 Kubernetes 集群组合在一起，并将它们视为单个实体进行交互。我们将涵盖的主题包括以下内容：

+   深入了解集群联邦的全部内容

+   如何准备、配置和管理集群联邦

+   如何在多个集群上运行联合工作负载

# 了解集群联邦

集群联邦在概念上很简单。您可以聚合多个 Kubernetes 集群，并将它们视为单个逻辑集群。有一个联邦控制平面，向客户端呈现系统的单一统一视图。

以下图表展示了 Kubernetes 集群联邦的整体情况：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-k8s/img/20ec9f25-71e9-4c28-b26c-bbb521b2dd32.png)

联邦控制平面由联邦 API 服务器和联邦控制器管理器共同协作。联邦 API 服务器将请求转发到联邦中的所有集群。此外，联邦控制器管理器通过将请求路由到各个联邦集群成员的更改来执行控制器管理器的职责。实际上，集群联邦并不是微不足道的，也不能完全抽象化。跨 Pod 通信和数据传输可能会突然产生大量的延迟和成本开销。让我们首先看一下集群联邦的用例，了解联合组件和资源的工作方式，然后再来研究难点：位置亲和性、跨集群调度和联邦数据访问。

# 集群联邦的重要用例

有四类用例受益于集群联邦。

# 容量溢出

公共云平台，如 AWS、GCE 和 Azure，非常好，并提供许多好处，但它们并不便宜。许多大型组织在自己的数据中心投入了大量资金。其他组织与私人服务提供商合作，如 OVS、Rackspace 或 Digital Ocean。如果您有能力自行管理和操作基础设施，那么在自己的基础设施上运行 Kubernetes 集群比在云中运行更经济。但是，如果您的一些工作负载波动并且在相对短的时间内需要更多的容量呢？

例如，您的系统可能在周末或节假日受到特别严重的打击。传统方法是只是提供额外的容量。但在许多动态情况下，这并不容易。通过容量溢出，您可以在本地数据中心或私人服务提供商上运行 Kubernetes 集群中运行大部分工作，并在其中一个大型平台提供商上运行基于云的 Kubernetes 集群。大部分时间，基于云的集群将被关闭（停止实例），但在需要时，您可以通过启动一些停止的实例来弹性地为系统增加容量。Kubernetes 集群联合可以使这种配置相对简单。它消除了许多关于容量规划和支付大部分时间未使用的硬件的头疼。

这种方法有时被称为**云爆发**。

# 敏感工作负载

这几乎是容量溢出的相反情况。也许您已经接受了云原生的生活方式，整个系统都在云上运行，但是一些数据或工作负载涉及敏感信息。监管合规性或您组织的安全政策可能要求数据和工作负载必须在完全由您控制的环境中运行。您的敏感数据和工作负载可能会受到外部审计。确保私有 Kubernetes 集群中的信息永远不会泄漏到基于云的 Kubernetes 集群可能至关重要。但是，希望能够查看公共集群并能够从私有集群启动非敏感工作负载可能是可取的。如果工作负载的性质可以动态地从非敏感变为敏感，那么就需要通过制定适当的策略和实施来解决。例如，您可以阻止工作负载改变其性质。或者，您可以迁移突然变得敏感的工作负载，并确保它不再在基于云的集群上运行。另一个重要的例子是国家合规性，根据法律要求，某些数据必须保留在指定的地理区域（通常是一个国家）内，并且只能从该地区访问。在这种情况下，必须在该地理区域创建一个集群。

# 避免供应商锁定

大型组织通常更喜欢有选择，并不希望被绑定在单一供应商上。风险往往太大，因为供应商可能会关闭或无法提供相同级别的服务。拥有多个供应商通常也有利于谈判价格。Kubernetes 旨在成为供应商无关的。您可以在不同的云平台、私有服务提供商和本地数据中心上运行它。

然而，这并不是微不足道的。如果您想确保能够快速切换供应商或将一些工作负载从一个供应商转移到另一个供应商，您应该已经在多个供应商上运行系统。您可以自己操作，或者有一些公司提供在多个供应商上透明运行 Kubernetes 的服务。由于不同的供应商运行不同的数据中心，您自动获得了一些冗余和对供应商范围内的故障的保护。

# 地理分布的高可用性

高可用性意味着即使系统的某些部分出现故障，服务仍将对用户保持可用。在联邦 Kubernetes 集群的背景下，故障的范围是整个集群，这通常是由于托管集群的物理数据中心出现问题，或者可能是平台提供商出现更广泛的问题。高可用性的关键是冗余。地理分布式冗余意味着在不同位置运行多个集群。这可能是同一云提供商的不同可用区，同一云提供商的不同地区，甚至完全不同的云提供商（参见“避免供应商锁定”部分）。在运行具有冗余的集群联邦时，有许多问题需要解决。我们稍后将讨论其中一些问题。假设技术和组织问题已经解决，高可用性将允许将流量从失败的集群切换到另一个集群。这对用户来说应该是透明的（切换期间的延迟，以及一些正在进行的请求或任务可能会消失或失败）。系统管理员可能需要采取额外步骤来支持切换和处理原始集群的故障。

# 联邦控制平面

联邦控制平面由两个组件组成，共同使得 Kubernetes 集群的联邦可以看作和作为一个统一的 Kubernetes 集群。

# 联邦 API 服务器

联邦 API 服务器正在管理组成联邦的 Kubernetes 集群。它在`etcd`数据库中管理联邦状态（即哪些集群是联邦的一部分），与常规 Kubernetes 集群一样，但它保持的状态只是哪些集群是联邦的成员。每个集群的状态存储在该集群的`etcd`数据库中。联邦 API 服务器的主要目的是与联邦控制器管理器进行交互，并将请求路由到联邦成员集群。联邦成员不需要知道它们是联邦的一部分：它们的工作方式完全相同。

以下图表展示了联邦 API 服务器、联邦复制控制器和联邦中的 Kubernetes 集群之间的关系：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-k8s/img/e89605d4-6f49-4385-87e2-6bf824bfb661.png)

# 联邦控制器管理器

联邦控制器管理器确保联邦的期望状态与实际状态匹配。它将任何必要的更改转发到相关的集群或集群。联邦控制器管理器二进制文件包含多个控制器，用于本章后面将介绍的所有不同的联邦资源。尽管控制逻辑相似：它观察变化并在集群状态偏离时将集群状态带到期望状态。这是针对集群联邦中的每个成员进行的。

以下图表展示了这个永久控制循环：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-k8s/img/6c1f2b1b-0bfc-4849-939c-3659eb76d1ab.png)

# 联邦资源

Kubernetes 联邦仍在不断发展中。截至 Kubernetes 1.10，只有一些标准资源可以进行联邦。我们将在这里介绍它们。要创建联邦资源，您可以使用 Kubectl 的`--context=federation-cluster`命令行参数。当您使用`--context=federation-cluster`时，该命令将发送到联邦 API 服务器，该服务器负责将其发送到所有成员集群。

# 联邦 ConfigMap

联邦 ConfigMaps 非常有用，因为它们帮助集中配置可能分布在多个集群中的应用程序。

# 创建联邦 ConfigMap

以下是创建联邦 ConfigMap 的示例：

```
> kubectl --context=federation-cluster create -f configmap.yaml  
```

正如您所看到的，创建单个 Kubernetes 集群中的 ConfigMap 时唯一的区别是上下文。创建联邦 ConfigMap 时，它存储在控制平面的`etcd`数据库中，但每个成员集群中也存储了一份副本。这样，每个集群可以独立运行，不需要访问控制平面。

# 查看联邦 ConfigMap

您可以通过访问控制平面或访问成员集群来查看 ConfigMap。要访问成员集群中的 ConfigMap，请在上下文中指定联邦集群成员名称：

```
> kubectl --context=cluster-1 get configmap configmap.yaml  
```

# 更新联邦 ConfigMap

重要的是要注意，通过控制平面创建时，ConfigMap 将在所有成员集群中都是相同的。然而，由于它除了在控制平面集群中存储外，还在每个集群中单独存储，因此没有单一的“真实”来源。可以（尽管不建议）稍后独立修改每个成员集群的 ConfigMap。这会导致联邦中的配置不一致。联邦中不同集群的不同配置有有效的用例，但在这些情况下，我建议直接配置每个集群。当你创建一个联邦 ConfigMap 时，你是在表明整个集群应该共享这个配置。然而，通常情况下，你会希望通过指定 `--context=federation-cluster` 来更新联邦集群中的所有 ConfigMap。

# 删除联邦 ConfigMap

没错，你猜对了。你像往常一样删除，但指定上下文：

```
> kubectl --context=federation-cluster delete configmap      
```

只有一个小小的变化。从 Kubernetes 1.10 开始，当你删除一个联邦 ConfigMap 时，每个集群中自动创建的单独的 ConfigMap 仍然存在。你必须在每个集群中分别删除它们。也就是说，如果你的联邦中有三个集群分别叫做 `cluster-1`、`cluster-2` 和 `cluster-3`，你将不得不运行这额外的三个命令来摆脱联邦中的 ConfigMap：

```
> kubectl --context=cluster-1 delete configmap
> kubectl --context=cluster-2 delete configmap
> kubectl --context=cluster-3 delete configmap 
```

这将在将来得到纠正。

# 联邦守护进程

联邦守护进程基本上与常规的 Kubernetes 守护进程相同。你通过控制平面创建它并与之交互（通过指定 `--context=federation-cluster`），控制平面将其传播到所有成员集群。最终，你可以确保你的守护程序在联邦的每个集群的每个节点上运行。

# 联邦部署

联邦部署更加智能。当您创建一个具有 X 个副本的联邦部署，并且您有*N*个集群时，默认情况下副本将在集群之间均匀分布。如果您有 3 个集群，并且联邦部署有 15 个 pod，那么每个集群将运行 5 个副本。与其他联邦资源一样，控制平面将存储具有 15 个副本的联邦部署，然后创建 3 个部署（每个集群一个），每个部署都有 5 个副本。您可以通过添加注释`federation.kubernetes.io/deployment-preferences`来控制每个集群的副本数量。截至 Kubernetes 1.10，联邦部署仍处于 Alpha 阶段。在将来，该注释将成为联邦部署配置中的一个正确字段。

# 联邦事件

联邦事件与其他联邦资源不同。它们仅存储在控制平面中，不会传播到底层 Kubernetes 成员集群。

您可以像往常一样使用`--context=federation-cluster`查询联邦事件：

```
> kubectl --context=federation-cluster get events  
```

# 联邦水平 Pod 扩展

最近在 Kubernetes 1.9 中作为 Alpha 功能添加了联邦**水平 Pod 扩展**（**HPA**）。为了使用它，您必须在启动 API 服务器时提供以下标志：

```
--runtime-config=api/all=true  
```

这是一个重要的功能，因为集群联合的主要动机之一是在没有手动干预的情况下在多个集群之间流畅地转移工作负载。联邦 HPA 利用了集群内的 HPA 控制器。联邦 HPA 根据请求的最大和最小副本数量在成员集群之间均匀分配负载。在将来，用户将能够指定更高级的 HPA 策略。

例如，考虑一个具有 4 个集群的联邦；我们希望始终至少有 6 个 pod 和最多有 16 个 pod 在运行。以下清单将完成工作：

```
apiVersion: autoscaling/v1 
kind: HorizontalPodAutoscaler 
metadata: 
  name: cool-app 
  namespace: default 
spec: 
  scaleTargetRef: 
    apiVersion: apps/v1beta1 
    kind: Deployment 
    name: cool-app 
  minReplicas: 6 
  maxReplicas: 16 
  targetCPUUtilizationPercentage: 80 
```

使用以下命令启动联邦 HPA：

```
> kubectl --context=federation-cluster create federated-hpa.yaml  
```

现在会发生什么？联邦控制平面将在 4 个集群中的每个集群中创建标准 HPA，最多有 4 个副本和最少有 2 个副本。原因是这是最经济地满足联邦要求的设置。让我们了解一下为什么。如果每个集群最多有 4 个副本，那么我们最多会有 4 x 4 = 16 个副本，这符合我们的要求。至少 2 个副本的保证意味着我们至少会有 4 x 2 = 8 个副本。这满足了我们至少会有 6 个副本的要求。请注意，即使系统上没有负载，我们也将始终至少有 8 个副本，尽管我们指定 6 个也可以。鉴于跨集群的均匀分布的限制，没有其他办法。如果集群 HPA 的`minReplicas=1`，那么集群中的总副本数可能是 4 x 1 = 4，这少于所需的联邦最小值 6。未来，用户可能可以指定更复杂的分布方案。

可以使用集群选择器（在 Kubernetes 1.7 中引入）来将联邦对象限制为成员的子集。因此，如果我们想要至少 6 个最多 15 个，可以将其均匀分布在 3 个集群中，而不是 4 个，每个集群将至少有 2 个最多 5 个。

# 联邦入口

联邦入口不仅在每个集群中创建匹配的入口对象。联邦入口的主要特点之一是，如果整个集群崩溃，它可以将流量引导到其他集群。从 Kubernetes 1.4 开始，联邦入口在 Google Cloud Platform 上得到支持，包括 GKE 和 GCE。未来，联邦入口将增加对混合云的支持。

联邦入口执行以下任务：

+   在联邦的每个集群成员中创建 Kubernetes 入口对象

+   为所有集群入口对象提供一个一站式逻辑 L7 负载均衡器，具有单个 IP 地址

+   监视每个集群中入口对象后面的服务后端 pod 的健康和容量

+   确保在各种故障情况下将客户端连接路由到健康的服务端点，例如 pod、集群、可用区或整个区域的故障，只要联邦中有一个健康的集群

# 创建联邦入口

通过寻址联邦控制平面来创建联邦入口

```
> kubectl --context=federation-cluster create -f ingress.yaml  
```

联合控制平面将在每个集群中创建相应的入口。所有集群将共享相同的命名空间和`ingress`对象的名称：

```
> kubectl --context=cluster-1 get ingress myingress
NAME        HOSTS     ADDRESS           PORTS     AGE
ingress      *         157.231.15.33    80, 443   1m  
```

# 使用联合入口进行请求路由

联合入口控制器将请求路由到最近的集群。入口对象通过`Status.Loadbalancer.Ingress`字段公开一个或多个 IP 地址，这些 IP 地址在入口对象的生命周期内保持不变。当内部或外部客户端连接到特定集群入口对象的 IP 地址时，它将被路由到该集群中的一个 pod。然而，当客户端连接到联合入口对象的 IP 地址时，它将自动通过最短的网络路径路由到请求源最近的集群中的一个健康 pod。因此，例如，来自欧洲互联网用户的 HTTP(S)请求将直接路由到具有可用容量的欧洲最近的集群。如果欧洲没有这样的集群，请求将被路由到下一个最近的集群（通常在美国）。

# 使用联合入口处理故障

有两种广义的失败类别：

+   Pod 故障

+   集群故障

Pod 可能因多种原因而失败。在正确配置的 Kubernetes 集群（无论是集群联合成员还是不是），pod 将由服务和 ReplicaSets 管理，可以自动处理 pod 故障。这不应影响联合入口进行的跨集群路由和负载均衡。整个集群可能由于数据中心或全球连接的问题而失败。在这种情况下，联合服务和联合 ReplicaSets 将确保联合中的其他集群运行足够的 pod 来处理工作负载，并且联合入口将负责将客户端请求从失败的集群中路由出去。为了从这种自动修复功能中受益，客户端必须始终连接到联合入口对象，而不是单个集群成员。

# 联合作业

联合作业与集群内作业类似。联合控制平面在基础集群中创建作业，并根据任务的并行性均匀分配负载，并跟踪完成情况。例如，如果联合有 4 个集群，并且您创建了一个并行性为 8 和完成数为 24 的联合作业规范，那么将在每个集群中创建一个并行性为 2 和完成数为 6 的作业。

# 联合命名空间

Kubernetes 命名空间在集群内用于隔离独立区域并支持多租户部署。联合命名空间在整个集群联合中提供相同的功能。API 是相同的。当客户端访问联合控制平面时，他们只能访问他们请求的命名空间，并且被授权访问联合中所有集群的命名空间。

您可以使用相同的命令并添加`--context=federation-cluster`：

```
> kubectl --context=federation-cluster create -f namespace.yaml
> kubectl --context=cluster-1 get namespaces namespace
> kubectl --context=federation-cluster create -f namespace.yaml  
```

# 联合复制 ReplicaSet

最好使用部署和联合部署来管理集群或联合中的副本。但是，如果出于某种原因您更喜欢直接使用 ReplicaSets 进行工作，那么 Kubernetes 支持联合`ReplicaSet`。没有联合复制控制器，因为 ReplicaSets 超越了复制控制器。

当您创建联合 ReplicaSets 时，控制平面的工作是确保整个集群中的副本数量与您的联合 ReplicaSets 配置相匹配。控制平面将在每个联合成员中创建一个常规 ReplicaSet。每个集群将默认获得相等（或尽可能接近相等）数量的副本，以便总数将达到指定的副本数量。

您可以使用以下注释来控制每个集群的副本数量：`federation.kubernetes.io/replica-set-preferences`。

相应的数据结构如下：

```
type FederatedReplicaSetPreferences struct { 
  Rebalance bool 
  Clusters map[string]ClusterReplicaSetPreferences 
} 
```

如果`Rebalance`为`true`，则正在运行的副本可能会根据需要在集群之间移动。集群映射确定每个集群的 ReplicaSets 偏好。如果将`*`指定为键，则所有未指定的集群将使用该偏好集。如果没有`*`条目，则副本将仅在映射中显示的集群上运行。属于联合但没有条目的集群将不会安排 pod（对于该 pod 模板）。

每个集群的单独 ReplicaSets 偏好使用以下数据结构指定：

```
type ClusterReplicaSetPreferences struct { 
  MinReplicas int64 
  MaxReplicas *int64 
  Weight int64 
} 
```

`MinReplicas`默认为`0`。`MaxReplicas`默认情况下是无限制的。权重表示向这个 ReplicaSets 添加额外副本的偏好，默认为`0`。

# 联合秘密

联合秘密很简单。当您通过控制平面像往常一样创建联合秘密时，它会传播到整个集群。就是这样。

# 困难的部分

到目前为止，联邦似乎几乎是直截了当的。将一堆集群组合在一起，通过控制平面访问它们，一切都会被复制到所有集群。但是有一些困难因素和基本概念使这种简化的观点变得复杂。Kubernetes 的许多功能来自于其在幕后执行大量工作的能力。在一个完全部署在单个物理数据中心或可用性区域的单个集群中，所有组件都连接到快速网络，Kubernetes 本身非常有效。在 Kubernetes 集群联邦中，情况就不同了。延迟、数据传输成本以及在集群之间移动 Pods 都有不同的权衡。根据用例，使联邦工作可能需要系统设计师和运营商额外的注意、规划和维护。此外，一些联合资源不如其本地对应物成熟，这增加了更多的不确定性。

# 联邦工作单元

Kubernetes 集群中的工作单元是 Pod。在 Kubernetes 中无法打破 Pod。整个 Pod 将始终一起部署，并受到相同的生命周期处理。Pod 是否应该保持集群联邦的工作单元？也许将更大的单元（如整个 ReplicaSet、部署或服务）与特定集群关联起来会更有意义。如果集群失败，整个 ReplicaSet、部署或服务将被调度到另一个集群。那么一组紧密耦合的 ReplicaSets 呢？这些问题的答案并不总是容易的，甚至可能随着系统的演变而动态改变。

# 位置亲和性

位置亲和力是一个主要关注点。Pods 何时可以分布在集群之间？这些 Pods 之间的关系是什么？是否有亲和力要求，比如 Pods 之间或 Pods 与其他资源（如存储）之间？有几个主要类别：

+   严格耦合

+   松散耦合

+   优先耦合

+   严格解耦

+   均匀分布

在设计系统以及如何在联邦中分配和调度服务和 Pods 时，确保始终尊重位置亲和性要求非常重要。

# 严格耦合

严格耦合的要求适用于必须在同一集群中的应用程序。如果对 pod 进行分区，应用程序将失败（可能是由于实时要求无法在集群间进行网络传输），或者成本可能太高（pod 可能正在访问大量本地数据）。将这种紧密耦合的应用程序移动到另一个集群的唯一方法是在另一个集群上启动完整的副本（包括数据），然后关闭当前集群上的应用程序。如果数据量太大，该应用程序可能实际上无法移动，并对灾难性故障敏感。这是最难处理的情况，如果可能的话，您应该设计系统以避免严格耦合的要求。

# 松耦合

松耦合的应用程序在工作负载尴尬地并行时表现最佳，每个 pod 不需要了解其他 pod 或访问大量数据。在这些情况下，pod 可以根据联邦中的容量和资源利用率安排到集群中。必要时，pod 可以在不出问题的情况下从一个集群移动到另一个集群。例如，一个无状态的验证服务执行一些计算，并在请求本身中获取所有输入，不查询或写入任何联邦范围的数据。它只验证其输入并向调用者返回有效/无效的判断。

# 优先耦合

在所有 pod 都在同一集群中或 pod 和数据共同位于同一位置时，优先耦合的应用程序表现更好，但这不是硬性要求。例如，它可以与仅需要最终一致性的应用程序一起工作，其中一些联邦范围的应用程序定期在所有集群之间同步应用程序状态。在这些情况下，分配是明确地针对一个集群进行的，但在压力下留下了一个安全舱口，可以在其他集群中运行或迁移。

# 严格解耦

一些服务具有故障隔离或高可用性要求，这要求在集群之间进行分区。如果所有副本最终可能被安排到同一集群中，那么运行关键服务的三个副本就没有意义，因为该集群只成为一个临时的单点故障（SPOF）。

# 均匀分布

均匀分布是指服务、ReplicaSet 或 pod 的实例必须在每个集群上运行。这类似于 DaemonSet，但不是确保每个节点上有一个实例，而是每个集群一个实例。一个很好的例子是由一些外部持久存储支持的 Redis 缓存。每个集群中的 pod 应该有自己的集群本地 Redis 缓存，以避免访问可能更慢或成为瓶颈的中央存储。另一方面，每个集群不需要超过一个 Redis 服务（它可以分布在同一集群中的几个 pod 中）。

# 跨集群调度

跨集群调度与位置亲和力相辅相成。当创建新的 pod 或现有的 pod 失败并且需要安排替代时，它应该去哪里？当前的集群联邦不能处理我们之前提到的所有场景和位置亲和力的选项。在这一点上，集群联邦很好地处理了松散耦合（包括加权分布）和严格耦合（通过确保副本的数量与集群的数量相匹配）的类别。其他任何情况都需要您不使用集群联邦。您将不得不添加自己的自定义联邦层，以考虑更多专门的问题，并且可以适应更复杂的调度用例。

# 联邦数据访问

这是一个棘手的问题。如果您有大量数据和在多个集群中运行的 pod（可能在不同的大陆上），并且需要快速访问它，那么您有几个不愉快的选择：

+   将数据复制到每个集群（复制速度慢，传输昂贵，存储昂贵，同步和处理错误复杂）

+   远程访问数据（访问速度慢，每次访问昂贵，可能成为单点故障）

+   制定一个复杂的混合解决方案，对一些最热门的数据进行每个集群缓存（复杂/陈旧的数据，仍然需要传输大量数据）

# 联邦自动扩展

目前不支持联邦自动调用。可以利用两个维度的扩展，以及组合：

+   每个集群的扩展

+   将集群添加/移除联邦

+   混合方法

考虑一个相对简单的场景，即在三个集群上运行一个松散耦合的应用程序，每个集群有五个 pod。在某个时候，15 个 pod 无法再处理负载。我们需要增加更多的容量。我们可以增加每个集群中的 pod 数量，但如果我们在联邦级别这样做，那么每个集群将有六个 pod 在运行。我们通过三个 pod 增加了联邦的容量，而只需要一个 pod。当然，如果您有更多的集群，问题会变得更糟。另一个选择是选择一个集群并只改变其容量。这是可能的，但现在我们明确地在整个联邦中管理容量。如果我们有许多集群运行数百个具有动态变化需求的服务，情况会很快变得复杂。

添加一个全新的集群更加复杂。我们应该在哪里添加新的集群？没有额外的可用性要求可以指导决策。这只是额外的容量问题。创建一个新的集群通常需要复杂的首次设置，并且可能需要几天来批准公共云平台上的各种配额。混合方法增加了联邦中现有集群的容量，直到达到某个阈值，然后开始添加新的集群。这种方法的好处是，当您接近每个集群的容量限制时，您开始准备新的集群，以便在必要时立即启动。除此之外，它需要大量的工作，并且您需要为灵活性和可伸缩性付出增加的复杂性。

# 管理 Kubernetes 集群联邦

管理 Kubernetes 集群联邦涉及许多超出管理单个集群的活动。有两种设置联邦的方式。然后，您需要考虑级联资源删除，跨集群负载平衡，跨集群故障转移，联邦服务发现和联邦发现。让我们详细讨论每一种。

# 从头开始设置集群联邦

注意：这种方法现在已经不推荐使用`Kubefed`。我在这里描述它是为了让使用较旧版本 Kubernetes 的读者受益。

建立 Kubernetes 集群联邦，我们需要运行控制平面的组件，如下所示：

```
etcd 
federation-apiserver 
federation-controller-manager 
```

其中一个最简单的方法是使用全能的 hyperkube 镜像：

[`github.com/kubernetes/kubernetes/tree/master/cluster/images/hyperkube`](https://github.com/kubernetes/kubernetes/tree/master/cluster/images/hyperkube)

联邦 API 服务器和联邦控制器管理器可以作为现有 Kubernetes 集群中的 pod 运行，但正如前面讨论的那样，最好从容错和高可用性的角度来看，将它们运行在自己的集群中。

# 初始设置

首先，您必须运行 Docker，并获取包含我们在本指南中将使用的脚本的 Kubernetes 版本。当前版本是 1.5.3。您也可以下载最新可用版本：

```
> curl -L https://github.com/kubernetes/kubernetes/releases/download/v1.5.3/kubernetes.tar.gz | tar xvzf -
> cd kubernetes  
```

我们需要为联邦配置文件创建一个目录，并将`FEDERATION_OUTPUT_ROOT`环境变量设置为该目录。为了方便清理，最好创建一个新目录：

```
> export FEDERATION_OUTPUT_ROOT="${PWD}/output/federation"
> mkdir -p "${FEDERATION_OUTPUT_ROOT}"  
```

现在，我们可以初始化联邦：

```
> federation/deploy/deploy.sh init 
```

# 使用官方的 Hyperkube 镜像

作为每个 Kubernetes 版本的一部分，官方发布的镜像都被推送到`gcr.io/google_containers`。要使用该存储库中的镜像，您可以将配置文件中的容器镜像字段设置为`${FEDERATION_OUTPUT_ROOT}`指向`gcr.io/google_containers/hyperkube`镜像，其中包括`federation-apiserver`和`federation-controller-manager`二进制文件。

# 运行联邦控制平面

我们准备通过运行以下命令部署联邦控制平面：

```
> federation/deploy/deploy.sh deploy_federation  
```

该命令将启动控制平面组件作为 pod，并为联邦 API 服务器创建一个`LoadBalancer`类型的服务，并为`etcd`创建一个由动态持久卷支持的持久卷索赔。

要验证联邦命名空间中的所有内容是否正确创建，请输入以下内容：

```
> kubectl get deployments --namespace=federation  
```

你应该看到这个：

```
NAME                        DESIRED CURRENT UP-TO-DATE      
federation-controller-manager   1         1         1 federation-apiserver 1         1         1 
```

您还可以使用 Kubectl config view 检查`kubeconfig`文件中的新条目。请注意，动态配置目前仅适用于 AWS 和 GCE。

# 向联邦注册 Kubernetes 集群

要向联邦注册集群，我们需要一个与集群通信的秘钥。

让我们在主机 Kubernetes 集群中创建秘钥。假设目标集群的`kubeconfig`位于`|cluster-1|kubeconfig`。您可以运行以下命令

创建`secret`：

```
> kubectl create secret generic cluster-1 --namespace=federation 
--from-file=/cluster-1/kubeconfig  
```

集群的配置看起来和这个一样：

```
apiVersion: federation/v1beta1 
kind: Cluster 
metadata: 
  name: cluster1 
spec: 
  serverAddressByClientCIDRs: 
  - clientCIDR: <client-cidr> 
    serverAddress: <apiserver-address> 
  secretRef: 
    name: <secret-name> 
```

我们需要设置`<client-cidr>`，`<apiserver-address>`和`<secret-name>`。这里的`<secret-name>`是您刚刚创建的秘密的名称。`serverAddressByClientCIDRs`包含客户端可以根据其 CIDR 使用的各种服务器地址。我们可以使用`CIDR 0.0.0.0/0`设置服务器的公共 IP 地址，所有客户端都将匹配。此外，如果要内部客户端使用服务器的`clusterIP`，可以将其设置为`serverAddress`。在这种情况下，客户端 CIDR 将是仅匹配在该集群中运行的 pod 的 IP 的 CIDR。

让我们注册集群：

```
> kubectl create -f /cluster-1/cluster.yaml --context=federation-cluster  
```

让我们看看集群是否已正确注册：

```
> kubectl get clusters --context=federation-cluster
NAME       STATUS    VERSION   AGE
cluster-1   Ready               1m 
```

# 更新 KubeDNS

集群已注册到联邦。现在是时候更新`kube-dns`，以便您的集群可以路由联邦服务请求。从 Kubernetes 1.5 或更高版本开始，通过`kube-dns ConfigMap`传递`--federations`标志来完成：

```
--federations=${FEDERATION_NAME}=${DNS_DOMAIN_NAME}    
```

`ConfigMap`的外观如下：

```
apiVersion: v1 
kind: ConfigMap 
metadata: 
  name: kube-dns 
  namespace: kube-system 
data: 
  federations: <federation-name>=<federation-domain-name> 
```

将`federation-name`和`federation-domain-name`替换为正确的值。

# 关闭联邦

如果要关闭联邦，只需运行以下命令：

```
federation/deploy/deploy.sh destroy_federation 
```

# 使用 Kubefed 设置集群联合

Kubernetes 1.5 引入了一个名为`Kubefed`的新的 Alpha 命令行工具，帮助您管理联合集群。`Kubefed`的工作是使部署新的 Kubernetes 集群联合控制平面变得容易，并向现有联合控制平面添加或删除集群。自 Kubernetes 1.6 以来一直处于 beta 阶段。

# 获取 Kubefed

直到 Kubernetes 1.9，Kubefed 是 Kubernetes 客户端二进制文件的一部分。您将获得 Kubectl 和 Kubefed。以下是在 Linux 上下载和安装的说明：

```
curl -LO https://storage.googleapis.com/kubernetes-release/release/${RELEASE-VERSION}/kubernetes-client-linux-amd64.tar.gztar -xzvf kubernetes-client-linux-amd64.tar.gz
    sudo cp kubernetes/client/bin/kubefed /usr/local/bin
    sudo chmod +x /usr/local/bin/kubefed
    sudo cp kubernetes/client/bin/kubectl /usr/local/bin
    sudo chmod +x /usr/local/bin/kubectl

```

如果您使用不同的操作系统或想安装不同的版本，则需要进行必要的调整。自 Kubernetes 1.9 以来，Kubefed 已在专用联邦存储库中可用：

```
curl -LO https://storage.cloud.google.com/kubernetes-federation-release/release/${RELEASE-VERSION}/federation-client-linux-amd64.tar.gztar -xzvf federation-client-linux-amd64.tar.gz
    sudo cp federation/client/bin/kubefed /usr/local/binsudo chmod +x /usr/local/bin/kubefed
```

您可以按照此处的说明单独安装 Kubectl：

```
https://kubernetes.io/docs/tasks/tools/install-kubectl/
```

# 选择主机集群

联邦控制平面可以是其自己的专用集群，也可以与现有集群一起托管。您需要做出这个决定。主机集群托管组成联邦控制平面的组件。确保您在本地`kubeconfig`中具有与主机集群对应的`kubeconfig`条目。

要验证是否具有所需的`kubeconfig`条目，请键入以下内容：

```
> kubectl config get-contexts  
```

您应该看到类似于这样的东西：

```
CURRENT   NAME      CLUSTER   AUTHINFO  NAMESPACE
cluster-1 cluster-1  cluster-1  
```

在部署联邦控制平面时，将稍后提供上下文名称`cluster-1`。

# 部署联邦控制平面

是时候开始使用 Kubefed 了。`kubefed init`命令需要三个参数：

+   联邦名称

+   主机集群上下文

+   用于您的联邦服务的域名后缀

以下示例命令部署了一个带有联邦控制平面的

名称联邦；一个主机集群上下文，`cluster-1`；一个 coredns DNS 提供程序（`google-clouddns`和`aes-route53`也是有效的）；和域后缀，`kubernetes-ftw.com`：

```
> kubefed init federation --host-cluster-context=cluster-1 --dns-provider coredns --dns-zone-name="kubernetes-ftw.com"  
```

DNS 后缀应该是您管理的 DNS 域名。

`kubefed init`在主机集群中设置联邦控制平面，并在本地`kubeconfig`中为联邦 API 服务器添加条目。由于错误，Kubernetes 可能不会创建默认命名空间。在这种情况下，您将不得不自己执行。键入以下命令：

```
> kubectl create namespace default --context=federation  
```

不要忘记将当前上下文设置为联邦，以便 Kubectl 将目标设置为联邦控制平面：

```
> kubectl config use-context federation 
```

# 联邦服务发现

联邦服务发现与联邦负载平衡紧密耦合。一个实用的设置包括一个全局 L7 负载均衡器，将请求分发到联邦集群中的联邦入口对象。

这种方法的好处是控制权留在 Kubernetes 联邦，随着时间的推移，它将能够与更多的集群类型（目前只有 AWS 和 GCE）一起工作，并了解集群利用率和其他约束。

拥有专用的查找服务并让客户端直接连接到各个集群上的服务的替代方案会失去所有这些好处。

# 将集群添加到联邦

一旦控制平面成功部署，我们应该将一些 Kubernetes 集群添加到联邦中。Kubefed 为此目的提供了`join`命令。`kubefed join`命令需要以下参数：

+   要添加的集群名称

+   主机集群上下文

例如，要将名为`cluster-2`的新集群添加到联邦中，请键入

以下：

```
kubefed join cluster-2 --host-cluster-context=cluster-1 
```

# 命名规则和自定义

您提供给`kubefed join`的集群名称必须是有效的 RFC 1035 标签。RFC 1035 只允许字母、数字和连字符，并且标签必须以字母开头。

此外，联邦控制平面需要加入集群的凭据才能对其进行操作。这些凭据是从本地的`kubeconfig`中获取的。`Kubefed join`命令使用指定为参数的集群名称来查找本地`kubeconfig`中的集群上下文。如果它找不到匹配的上下文，它将以错误退出。

这可能会导致问题，因为联邦中每个集群的上下文名称不遵循 RFC 1035 标签命名规则。在这种情况下，您可以指定符合 RFC 1035 标签命名规则的集群名称，并使用`--cluster-context`标志指定集群上下文。例如，如果您要加入的集群的上下文是`cluster-3`（不允许使用下划线），您可以通过运行此命令加入该集群：

```
kubefed join cluster-3 --host-cluster-context=cluster-1 --cluster-context=cluster-3  
```

# 秘密名称

联邦控制平面在上一节中描述的集群凭据作为主机集群中的一个秘密存储。秘密的名称也是从集群名称派生的。

但是，在 Kubernetes 中`secret`对象的名称应符合 RFC 1123 中描述的 DNS 子域名规范。如果不是这种情况，您可以使用`--secret-name`标志将`secret name`传递给`kubefed join`。例如，如果集群名称是`cluster-4`，`secret name`是`4secret`（不允许以字母开头），您可以通过运行此命令加入该集群：

```
kubefed join cluster-4 --host-cluster-context=cluster-1 --secret-name=4secret  
```

`kubefed join`命令会自动为您创建秘密。

# 从联邦中删除一个集群

要从联邦中删除一个集群，请使用集群名称和联邦主机集群上下文运行`kubefed unjoin`命令：

```
kubefed unjoin cluster-2 --host-cluster-context=cluster-1  
```

# 关闭联邦

在 Kubefed 的 beta 版本中，联邦控制平面的适当清理尚未完全实现。但是，暂时删除联邦系统命名空间应该会删除除联邦控制平面的`etcd`动态配置的持久存储卷之外的所有资源。您可以通过运行以下命令`delete`联邦命名空间来删除联邦命名空间：

```
> kubectl delete ns federation-system  
```

# 资源的级联删除

Kubernetes 集群联邦通常在控制平面中管理联合对象，以及每个成员 Kubernetes 集群中的相应对象。级联删除联合对象意味着成员 Kubernetes 集群中的相应对象也将被删除。

这不会自动发生。默认情况下，只删除联合控制平面对象。要激活级联删除，您需要设置以下选项：

```
DeleteOptions.orphanDependents=false 
```

在 Kuberentes 1.5 中，只有以下联合对象支持级联删除：

+   部署

+   守护进程集

+   入口管理

+   命名空间

+   副本集

+   秘密

对于其他对象，您必须进入每个集群并明确删除它们。幸运的是，从 Kubernetes 1.6 开始，所有联合对象都支持级联删除。

# 跨多个集群的负载均衡

跨集群的动态负载均衡并不是微不足道的。最简单的解决方案是说这不是 Kubernetes 的责任。负载均衡将在 Kubernetes 集群联合之外执行。但考虑到 Kubernetes 的动态特性，即使外部负载均衡器也必须收集关于每个集群上正在运行的服务和后端 pod 的大量信息。另一种解决方案是联合控制平面实现一个作为整个联合的流量导向器的 L7 负载均衡器。在较简单的用例中，每个服务在一个专用集群上运行，负载均衡器只是将所有流量路由到该集群。在集群故障的情况下，服务被迁移到另一个集群，负载均衡器现在将所有流量路由到新的集群。这提供了一个粗略的故障转移和集群级别的高可用性解决方案。

最佳解决方案将能够支持联合服务，并考虑其他因素，例如以下因素：

+   客户端的地理位置

+   每个集群的资源利用率

+   资源配额和自动扩展

以下图表显示了 GCE 上的 L7 负载均衡器如何将客户端请求分发到最近的集群：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-k8s/img/1add4f66-0a86-4972-a9b5-cc887d731c95.png)

# 跨多个集群的故障转移

联合故障转移很棘手。假设联合中的一个集群失败；一个选择是让其他集群接管工作。现在的问题是，如何在其他集群之间分配负载？

+   统一吗？

+   启动一个新的集群？

+   选择一个尽可能接近的现有集群（可能在同一地区）？

这些解决方案与联合负载平衡有微妙的相互作用，

地理分布的高可用性，跨不同集群的成本管理，

和安全。

现在，失败的集群再次上线。它应该逐渐重新接管其原始工作负载吗？如果它回来了，但容量减少或网络不稳定怎么办？有许多故障模式的组合可能使恢复变得复杂。

# 联邦迁移

联邦迁移与我们讨论过的几个主题相关，例如位置亲和性、联邦调度和高可用性。在其核心，联邦迁移意味着将整个应用程序或其部分从一个集群移动到另一个集群（更一般地从 M 个集群移动到 N 个集群）。联邦迁移可能是对各种事件的响应，例如以下事件：

+   集群中的低容量事件（或集群故障）

+   调度策略的更改（我们不再使用云提供商 X）

+   资源定价的更改（云提供商 Y 降低了价格，所以让我们迁移到那里）

+   联邦中添加或删除了一个新集群（让我们重新平衡应用程序的 Pods）

严格耦合的应用程序可以轻松地一次移动一个 Pod 或整个 Pod 到一个或多个集群（在适用的策略约束条件下，例如“仅限私有云”）。

对于优先耦合的应用程序，联邦系统必须首先找到一个具有足够容量来容纳整个应用程序的单个集群，然后预留该容量，并逐步将应用程序的一个（或多个）资源在一定的时间段内移动到新集群中（可能在预定义的维护窗口内）。

严格耦合的应用程序（除了被认为完全不可移动的应用程序）需要联邦系统执行以下操作：

+   在目标集群中启动整个副本应用程序

+   将持久数据复制到新的应用程序实例（可能在之前

启动 Pods）

+   切换用户流量

+   拆除原始应用程序实例

# 发现联邦服务

Kubernetes 提供 KubeDNS 作为内置核心组件。 KubeDNS 使用

`cluster-local` DNS 服务器以及命名约定来组成合格的

（按命名空间）DNS 名称约定。例如，`the-service`解析为默认`namespace`中的`the-service`服务，而`the-service.the-namespace`解析为`the-namespace namespace`中名为`the-service`的服务，该服务与默认的`the-service`不同。Pod 可以使用 KubeDNS 轻松找到和访问内部服务。Kubernetes 集群联邦将该机制扩展到多个集群。基本概念是相同的，但增加了另一级联邦。现在服务的 DNS 名称由`<service name>.<namespace name>.<federation name>`组成。这样，仍然可以使用原始的`<service name>.<namepace name>`命名约定来访问内部服务。但是，想要访问联邦服务的客户端使用联邦名称，最终将被转发到联邦成员集群中的一个来处理请求。

这种联邦限定的命名约定还有助于防止内部集群流量错误地到达其他集群。

使用前面的 NGINX 示例服务和刚刚描述的联邦服务 DNS 名称形式，让我们考虑一个例子：位于 cluster-1 可用区的集群中的一个 pod 需要访问 NGINX 服务。它现在可以使用服务的联邦 DNS 名称，即`nginx.the-namespace.the-federation`，这将自动扩展并解析为 NGINX 服务的最近健康的分片，无论在世界的哪个地方。如果本地集群中存在健康的分片，该服务的集群本地（通常为`10.x.y.z`）IP 地址将被返回（由集群本地的 KubeDNS）。这几乎等同于非联邦服务解析（几乎因为 KubeDNS 实际上为本地联邦服务返回了 CNAME 和 A 记录，但应用程序对这种微小的技术差异是无感的）。

然而，如果服务在本地集群中不存在（或者没有健康的后端 pod），DNS 查询会自动扩展。

# 运行联邦工作负载

联合工作负载是在多个 Kubernetes 集群上同时处理的工作负载。这对于松散耦合和分布式应用程序来说相对容易。然而，如果大部分处理可以并行进行，通常在最后会有一个连接点，或者至少需要查询和更新一个中央持久存储。如果同一服务的多个 pod 需要在集群之间合作，或者一组服务（每个服务可能都是联合的）必须共同工作并同步以完成某些任务，情况就会变得更加复杂。

Kubernetes 联合支持提供了联合工作负载的良好基础的联合服务。

联合服务的一些关键点是服务发现，跨集群

负载均衡和可用性区容错。

# 创建联合服务

联合服务在联合成员集群中创建相应的服务。

例如，要创建一个联合 NGINX 服务（假设您在`nginx.yaml`中有服务配置），请输入以下内容：

```
> kubectl --context=federation-cluster create -f nginx.yaml 
```

您可以验证每个集群中是否创建了一个服务（例如，在`cluster-2`中）：

```
> kubectl --context=cluster-2 get services nginx
NAME      CLUSTER-IP     EXTERNAL-IP      PORT(S)   AGE
nginx     10.63.250.98   104.199.136.89   80/TCP    9m 
```

所有集群中创建的服务将共享相同的命名空间和服务名称，这是有道理的，因为它们是一个单一的逻辑服务。

您的联合服务的状态将自动反映基础 Kubernetes 服务的实时状态：

```
> kubectl --context=federation-cluster describe services nginx
Name:                   nginx
Namespace:              default
Labels:                 run=nginx
Selector:               run=nginx
Type:                   LoadBalancer
IP: 
LoadBalancer Ingress:   105.127.286.190, 122.251.157.43, 114.196.14.218, 114.199.176.99, ...
Port:                   http    80/TCP
Endpoints:              <none>
Session Affinity:       None
No events.  
```

# 添加后端 pod

截至 Kubernetes 1.10，我们仍然需要将后端 pod 添加到每个联合成员集群。这可以通过`kubectl run`命令完成。在将来的版本中，Kubernetes 联合 API 服务器将能够自动执行此操作。这将节省一步。请注意，当您使用`kubectl run`命令时，Kubernetes 会根据镜像名称自动向 pod 添加运行标签。在下面的示例中，该示例在五个 Kubernetes 集群上启动了一个 NGINX 后端 pod，镜像名称为`nginx`（忽略版本），因此将添加以下标签：

```
run=nginx 
```

这是因为服务使用该标签来识别其 pod。如果使用另一个标签，需要显式添加它：

```
for C in cluster-1 
    cluster-2 
    cluster-3 
    cluster-4 
              cluster-5
    do
      kubectl --context=$C run nginx --image=nginx:1.11.1-alpine --port=80
    done

```

# 验证公共 DNS 记录

一旦前面的 pod 成功启动并监听连接，Kubernetes 将把它们报告为该集群中服务的健康端点（通过自动健康检查）。Kubernetes 集群联邦将进一步考虑这些服务分片中的每一个为健康，并通过自动配置相应的公共 DNS 记录将它们放入服务中。你可以使用你配置的 DNS 提供商的首选界面来验证这一点。例如，你的联邦可能配置为使用 Google Cloud DNS 和一个托管的 DNS 域，`example.com`：

```
> gcloud dns managed-zones describe example-dot-com 
creationTime: '2017-03-08T18:18:39.229Z'
description: Example domain for Kubernetes Cluster Federation
dnsName: example.com.
id: '7228832181334259121'
kind: dns#managedZone
name: example-dot-com
nameServers:
- ns-cloud-a1.googledomains.com.
- ns-cloud-a2.googledomains.com.
- ns-cloud-a3.googledomains.com.
- ns-cloud-a4.googledomains.com.
```

跟进以下命令以查看实际的 DNS 记录：

```
> gcloud dns record-sets list --zone example-dot-com  
```

如果你的联邦配置为使用`aws route53` DNS 服务，请使用以下命令：

```
> aws route53 list-hosted-zones  
```

然后使用这个命令：

```
> aws route53 list-resource-record-sets --hosted-zone-id K9PBY0X1QTOVBX  
```

当然，你可以使用标准的 DNS 工具，比如`nslookup`或`dig`来验证 DNS 记录是否被正确更新。你可能需要等一会儿才能使你的更改传播开来。或者，你可以直接指向你的 DNS 提供商：

```
> dig @ns-cloud-e1.googledomains.com ... 
```

然而，我总是更喜欢在 DNS 更改在正确传播后观察它们的变化，这样我就可以通知用户一切都准备就绪。

# DNS 扩展

如果服务在本地集群中不存在（或者存在但没有健康的后端 pod），DNS 查询会自动扩展，以找到最接近请求者可用区域的外部 IP 地址。KubeDNS 会自动执行这个操作，并返回相应的`CNAME`。这将进一步解析为服务的一个后备 pod 的 IP 地址。

你不必依赖自动 DNS 扩展。你也可以直接提供特定集群中或特定区域中服务的`CNAME`。例如，在 GCE/GKE 上，你可以指定`nginx.the-namespace.svc.europe-west1.example.com`。这将被解析为欧洲某个集群中服务的一个后备 pod 的 IP 地址（假设那里有集群和健康的后备 pod）。

外部客户端无法使用 DNS 扩展，但如果他们想要针对联邦的某个受限子集（比如特定区域），他们可以提供服务的完全限定的`CNAME`，就像例子一样。由于这些名称往往又长又笨重，一个好的做法是添加一些静态方便的`CNAME`记录：

```
eu.nginx.example.com        CNAME nginx.the-namespace.the-federation.svc.europe-west1.example.com.
us.nginx.example.com        CNAME nginx.the-namespace.the-federation.svc.us-central1.example.com.
nginx.example.com           CNAME nginx.the-namespace.the-federation.svc.example.com.  
```

下图显示了联邦查找在多个集群中是如何工作的：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-k8s/img/07c14135-6427-484a-93c4-08f0e73fd168.png)

# 处理后端 pod 和整个集群的故障

Kubernetes 将在几秒内将无响应的 Pod 从服务中移除。联邦控制平面监视集群的健康状况，以及不同集群中联邦服务的所有分片后面的端点。根据需要，它将将它们加入或移出服务，例如当服务后面的所有端点、整个集群或整个可用区都宕机时。DNS 缓存的固有延迟（默认情况下联邦服务 DNS 记录为 3 分钟），可能会在发生灾难性故障时将客户端的故障转移至另一个集群。然而，考虑到每个区域服务端点可以返回的离散 IP 地址数量（例如，`us-central1`有三个备用项），许多客户端将在比这更短的时间内自动切换到其中一个备用 IP，前提是进行了适当的配置。

# 故障排除

当事情出现问题时，您需要能够找出问题所在以及如何解决。以下是一些常见问题以及如何诊断/解决它们。

# 无法连接到联邦 API 服务器

请参考以下解决方案：

+   验证联邦 API 服务器正在运行

+   验证客户端（Kubectl）是否正确配置了适当的 API 端点和凭据

# 联邦服务成功创建，但基础集群中未创建服务

+   验证集群是否已注册到联邦

+   验证联邦 API 服务器能够连接并对所有集群进行身份验证

+   检查配额是否足够

+   检查日志是否有其他问题：

```
   Kubectl logs federation-controller-manager --namespace federation
```

# 总结

在本章中，我们已经涵盖了 Kubernetes 集群联邦的重要主题。集群联邦仍处于测试阶段，有些粗糙，但已经可以使用。部署并不多，目前官方支持的目标平台是 AWS 和 GCE/GKE，但云联邦背后有很大的动力。这对于在 Kubernetes 上构建大规模可扩展系统非常重要。我们讨论了 Kubernetes 集群联邦的动机和用例，联邦控制平面组件以及联邦 Kubernetes 对象。我们还研究了联邦的一些不太受支持的方面，比如自定义调度、联邦数据访问和自动扩展。然后，我们看了如何运行多个 Kubernetes 集群，包括设置 Kubernetes 集群联邦，向联邦添加和移除集群以及负载平衡、联邦故障转移、服务发现和迁移。然后，我们深入研究了在多个集群上运行联合工作负载的情况，包括联合服务以及与此场景相关的各种挑战。

到目前为止，您应该对联邦的当前状态有清晰的了解，知道如何利用 Kubernetes 提供的现有功能，并了解您需要自己实现哪些部分来增强不完整或不成熟的功能。根据您的用例，您可能会决定现在还为时过早，或者您想要冒险尝试。致力于 Kubernetes 联邦的开发人员行动迅速，因此很可能在您需要做出决定时，它将更加成熟和经过实战检验。

在下一章中，我们将深入研究 Kubernetes 的内部结构以及如何自定义它。Kubernetes 的一个显著的架构原则是，它可以通过一个完整的 REST API 进行访问。Kubectl 命令行工具是建立在 Kubernetes API 之上的，并为 Kubernetes 的整个范围提供交互性。然而，编程 API 访问为您提供了许多灵活性，以增强和扩展 Kubernetes。许多语言中都有客户端库，允许您从外部利用 Kubernetes 并将其集成到现有系统中。

除了其 REST API 之外，Kubernetes 在设计上是一个非常模块化的平台。它的核心操作的许多方面都可以定制和/或扩展。特别是，你可以添加用户定义的资源，并将它们与 Kubernetes 对象模型集成，并从 Kubernetes 的管理服务、`etcd`中的存储、通过 API 的暴露以及对内置和自定义对象的统一访问中受益。

我们已经看到了一些非常可扩展的方面，比如通过 CNI 插件和自定义存储类进行网络和访问控制。然而，Kubernetes 甚至可以让你定制调度器本身，这个调度器控制着 pod 分配到节点上。
