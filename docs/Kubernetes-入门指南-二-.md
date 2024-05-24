# Kubernetes 入门指南（二）

> 原文：[`zh.annas-archive.org/md5/1794743BB21D72736FFE64D66DCA9F0E`](https://zh.annas-archive.org/md5/1794743BB21D72736FFE64D66DCA9F0E)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：更新、渐进式发布和自动扩展

本章将扩展核心概念，向您展示如何在最小中断上线时间内推出更新并测试应用程序的新功能。它将介绍进行应用程序更新、渐进式发布和 A/B 测试的基础知识。此外，我们还将了解如何扩展 Kubernetes 集群本身。

本章将讨论以下主题：

+   应用程序扩展

+   滚动更新

+   A/B 测试

+   应用程序自动扩展

+   扩展您的集群

从版本 1.2 开始，Kubernetes 发布了一个部署 API。在处理扩展和应用程序更新方面，部署是推荐的方法。然而，在撰写本书时，它仍被视为测试版，而滚动更新已经稳定了几个版本。本章将探讨滚动更新作为引入扩展概念的一种方法，然后在下一章深入探讨使用部署的首选方法。

# 示例设置

在探索 Kubernetes 中用于扩展和更新的各种功能之前，我们将需要一个新的示例环境。我们将使用具有蓝色背景的先前容器映像的变体（请参考本章后面的*v0.1 和 v0.2（并排）*图像进行比较）。我们有以下代码：

```
apiVersion: v1 
kind: ReplicationController 
metadata: 
  name: node-js-scale 
  labels: 
    name: node-js-scale 
spec: 
  replicas: 1 
  selector: 
    name: node-js-scale 
  template: 
    metadata: 
      labels: 
        name: node-js-scale 
    spec: 
      containers: 
      - name: node-js-scale 
        image: jonbaier/pod-scaling:0.1 
        ports: 
        - containerPort: 80

```

*列表 4-1*：`pod-scaling-controller.yaml`

```
apiVersion: v1 
kind: Service 
metadata: 
  name: node-js-scale 
  labels: 
    name: node-js-scale 
spec: 
  type: LoadBalancer 
  sessionAffinity: ClientIP 
  ports: 
  - port: 80 
  selector: 
    name: node-js-scale

```

*列表 4-2*：`pod-scaling-service.yaml`

使用以下命令创建这些服务：

```
$ kubectl create -f pod-scaling-controller.yaml
$ kubectl create -f pod-scaling-service.yaml

```

服务的公共 IP 地址可能需要一段时间才能创建。

# 扩展

随着时间推移，在 Kubernetes 集群中运行应用程序时，您会发现一些应用程序需要更多资源，而其他应用程序可以使用更少的资源。我们希望有一种更无缝的方式来使我们的应用程序进行扩展。而不是删除整个 RC（及其关联的 pod）。

幸运的是，Kubernetes 包含一个`scale`命令，专门用于此目的。`scale`命令既适用于复制控制器，也适用于新的部署抽象。目前，我们将使用复制控制器探索其用法。在我们的新示例中，只有一个副本在运行。您可以使用`get pods`命令来检查：

```
$ kubectl get pods -l name=node-js-scale

```

让我们尝试使用以下命令将其扩展到三个：

```
$ kubectl scale --replicas=3 rc/node-js-scale

```

如果一切顺利，您将在终端窗口的输出中看到`scaled`一词。

可选地，您可以指定`--current-replicas`标志作为验证步骤。只有当前正在运行的副本数与此计数匹配时，才会进行扩展。

再次列出我们的 pods 后，现在应该看到三个名称类似`node-js-scale-**XXXXX**`的正在运行的 pods，其中`X`字符是一个随机字符串。

您也可以使用`scale`命令减少副本的数量。在任何情况下，`scale`命令都会添加或删除必要的 pod 副本，并且服务会自动更新和在新的或剩余的副本之间平衡。

# 平滑的更新

当我们的资源需求发生变化时，我们的应用程序进行上下缩放是许多生产场景中很有用的，但是对于简单的应用程序更新呢？任何生产系统都会有代码更新、补丁和功能添加。这些可能每月、每周甚至每天都在发生。确保我们有可靠的方法来推送这些变更而不会中断用户是一个首要考虑因素。

再次，我们受益于 Kubernetes 系统建立在多年经验基础上。1.0 版本内置了对滚动更新的支持。`rolling-update` 命令允许我们更新整个 RC 或仅更新每个副本使用的底层 Docker 镜像。我们还可以指定更新间隔，这将允许我们逐个更新一个 pod，并等待继续下一个。

让我们以我们的缩放示例为例，并对我们容器映像的 0.2 版本执行滚动更新。我们将使用 2 分钟的更新间隔，这样我们可以观察到进程如何进行：

```
$ kubectl rolling-update node-js-scale --image=jonbaier/pod-scaling:0.2 --update-period="2m"

```

您应该会看到一些关于创建名为 `node-js-scale-XXXXX` 的新 RC 的文本，其中 `X` 字符将是一串随机的数字和字母。此外，您将看到一个循环的开始，它开始一个新版本的副本，并从现有 RC 中删除一个。这个过程将继续，直到新的 RC 具有完整的副本计数运行。

如果我们想实时跟踪，可以打开另一个终端窗口，并使用 `get pods` 命令，再加上一个标签过滤器，来查看正在发生的情况：

```
$ kubectl get pods -l name=node-js-scale

```

此命令将筛选出名称中带有 `node-js-scale` 的 pod。如果在发出 `rolling-update` 命令后运行此命令，您应该会看到几个 pod 在运行，因为它逐个创建新版本并逐个删除旧版本。

前面 `rolling-update` 命令的完整输出应该看起来像下面的截图一样：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_04_01.png)

缩放输出

正如我们在这里所看到的，Kubernetes 首先创建了一个名为 `node-js-scale-10ea08ff9a118ac6a93f85547ed28f6` 的新 RC。然后，K8s 逐个循环，创建一个新的 pod 在新的控制器中，并从旧的控制器中删除一个。这个过程会持续到新的控制器达到完整的副本数量，而旧的控制器为零。之后，旧的控制器被删除，新的控制器被重命名为原始的控制器名称。

如果现在运行 `get pods` 命令，您会注意到所有的 pod 仍然有一个更长的名称。或者，我们可以在命令中指定一个新控制器的名称，Kubernetes 将使用该名称创建一个新的 RC 和 pod。再次，更新完成后，旧名称的控制器简单消失了。我建议您为更新后的控制器指定一个新名称，以避免以后在 pod 命名中造成混淆。使用此方法的相同 `update` 命令将如下所示：

```
$ kubectl rolling-update node-js-scale node-js-scale-v2.0 --image=jonbaier/pod-scaling:0.2 --update-period="2m"

```

利用我们在第一节创建的服务的静态外部 IP 地址，我们可以在浏览器中打开该服务。我们应该看到我们的标准容器信息页面。但是，你会注意到标题现在显示为 Pod 缩放 v0.2，背景为浅黄色：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_04_02-1.png)

v0.1 和 v0.2（并列）

值得注意的是，在整个更新过程中，我们只关注了 pod 和 RC。我们没有对我们的服务做任何操作，但服务仍然正常运行，并且现在指向我们的 pod 的新版本。这是因为我们的服务正在使用标签选择器进行成员身份验证。因为我们的旧副本和新副本都使用相同的标签，所以服务没有问题使用新副本来提供请求服务。更新是逐个 pod 进行的，所以对于服务的用户来说是无缝的。

# 测试、发布和切换

滚动更新功能可以很好地适用于简单的蓝绿部署场景。但是，在具有多个应用程序堆栈的实际蓝绿部署中，可能存在各种相互依赖关系，需要进行深入测试。`update-period` 命令允许我们添加一个 `timeout` 标志，其中可以进行一些测试，但这并不总是令人满意的测试目的。

类似地，您可能希望部分更改持续时间更长，一直到负载均衡器或服务级别。例如，您可能希望在一部分用户身上运行新用户界面功能的 A/B 测试。另一个例子是在新添加的集群节点等新基础设施上运行您应用程序的金丝雀发布（在这种情况下是副本）。

让我们看一个 A/B 测试的例子。对于此示例，我们需要创建一个新的服务，该服务使用 `sessionAffinity`。我们将亲和性设置为 `ClientIP`，这将允许我们将客户端转发到相同的后端 pod。这是关键的，如果我们希望我们的一部分用户看到一个版本，而其他用户看到另一个版本：

```
apiVersion: v1 
kind: Service 
metadata: 
  name: node-js-scale-ab 
  labels: 
    service: node-js-scale-ab 
spec: 
  type: LoadBalancer 
  ports: 
  - port: 80 
  sessionAffinity: ClientIP 
  selector: 
    service: node-js-scale-ab

```

*清单 4-3：*`pod-AB-service.yaml`

像往常一样使用 `create` 命令创建此服务，如下所示：

```
$ kubectl create -f pod-AB-service.yaml

```

这将创建一个指向我们运行应用程序版本 0.2 和 0.3 的 pod 的服务。接下来，我们将创建两个 RC，用于创建应用程序的两个副本。一个集合将具有应用程序版本 0.2，另一个将具有版本 0.3，如下所示：

```
apiVersion: v1 
kind: ReplicationController 
metadata: 
  name: node-js-scale-a 
  labels: 
    name: node-js-scale-a 
    version: "0.2" 
    service: node-js-scale-ab 
spec: 
  replicas: 2 
  selector: 
    name: node-js-scale-a 
    version: "0.2" 
    service: node-js-scale-ab 
  template: 
    metadata: 
      labels: 
        name: node-js-scale-a 
        version: "0.2" 
        service: node-js-scale-ab 
    spec: 
      containers: 
      - name: node-js-scale 
        image: jonbaier/pod-scaling:0.2 
        ports: 
        - containerPort: 80 
        livenessProbe: 
          # An HTTP health check 
          httpGet: 
            path: / 
            port: 80 
          initialDelaySeconds: 30 
          timeoutSeconds: 5 
        readinessProbe: 
          # An HTTP health check 
          httpGet: 
            path: / 
            port: 80 
          initialDelaySeconds: 30 
          timeoutSeconds: 1

```

*清单 4-4：*`pod-A-controller.yaml`

```
apiVersion: v1 
kind: ReplicationController 
metadata: 
  name: node-js-scale-b 
  labels: 
    name: node-js-scale-b 
    version: "0.3" 
    service: node-js-scale-ab 
spec: 
  replicas: 2 
  selector: 
    name: node-js-scale-b 
    version: "0.3" 
    service: node-js-scale-ab 
  template: 
    metadata: 
      labels: 
        name: node-js-scale-b 
        version: "0.3" 
        service: node-js-scale-ab 
    spec: 
      containers: 
      - name: node-js-scale 
        image: jonbaier/pod-scaling:0.3 
        ports: 
        - containerPort: 80 
        livenessProbe: 
          # An HTTP health check 
          httpGet: 
            path: / 
            port: 80 
          initialDelaySeconds: 30 
          timeoutSeconds: 5 
        readinessProbe: 
          # An HTTP health check 
          httpGet: 
            path: / 
            port: 80 
          initialDelaySeconds: 30 
          timeoutSeconds: 1

```

*清单 4-5：*`pod-B-controller.yaml`

请注意，我们有相同的服务标签，因此这些副本也将根据此选择器添加到服务池中。我们还定义了 `livenessProbe` 和 `readinessProbe` 来确保我们的新版本按预期工作。同样，使用 `create` 命令启动控制器：

```
$ kubectl create -f pod-A-controller.yaml
$ kubectl create -f pod-B-controller.yaml

```

现在我们的服务已平衡到应用程序的两个版本。在一个真正的 A/B 测试中，我们现在希望开始收集对每个版本的访问指标。同样，我们将`sessionAffinity`设置为`ClientIP`，所以所有请求都将发送到相同的 pod。一些用户将看到 v0.2，一些用户将看到 v0.3。

因为我们打开了`sessionAffinity`，所以您的测试可能每次都会显示相同的版本。这是正常现象，您需要尝试从多个 IP 地址连接以查看每个版本的用户体验。

由于每个版本都在自己的 pod 上，可以轻松地分离日志甚至在 pod 定义中添加一个日志容器以实现旁车日志模式。为简洁起见，在本书中我们不会介绍这种设置，但我们将在第八章中介绍一些日志工具，*监视和日志记录*。

我们可以看到这个过程将如何对金丝雀发布或手动蓝绿部署有所帮助。我们还可以看到启动新版本并逐渐过渡到新版本的过程是多么容易。

让我们快速看一下基本过渡。这实际上就是几个`scale`命令，如下所示：

```
$ kubectl scale --replicas=3 rc/node-js-scale-b
$ kubectl scale --replicas=1 rc/node-js-scale-a
$ kubectl scale --replicas=4 rc/node-js-scale-b
$ kubectl scale --replicas=0 rc/node-js-scale-a

```

使用`get pods`命令结合`-l`过滤器在`scale`命令之间观察转换过程。

现在，我们已完全过渡到版本 0.3（`node-js-scale-b`）。所有用户现在都将看到站点的版本 0.3。我们有版本 0.3 的四个副本，没有 0.2 的。如果运行`get rc`命令，您会注意到我们仍然有一个 0.2 的 RC（`node-js-scale-a`）。作为最后的清理，我们可以完全删除该控制器，如下所示：

```
$ kubectl delete rc/node-js-scale-a

```

# 应用自动扩展

Kubernetes 最近增加的一个功能是**水平 Pod 自动缩放器**。这种资源类型非常有用，因为它为我们提供了自动设置应用程序扩展阈值的方式。目前，该支持仅针对 CPU，但也有自定义应用程序指标的 alpha 支持。

让我们使用本章开头的`node-js-scale`复制控制器，并加上一个自动扩缩组件。在开始之前，让我们确保使用以下命令缩减到一个副本：

```
$ kubectl scale --replicas=1 rc/node-js-scale

```

现在我们可以创建一个水平 Pod 自动缩放器，其定义如下：

```
apiVersion: autoscaling/v1
kind: HorizontalPodAutoscaler
metadata:
  name: node-js-scale
spec:
  minReplicas: 1
  maxReplicas: 3
  scaleTargetRef:
    apiVersion: v1
    kind: ReplicationController
    name: node-js-scale
  targetCPUUtilizationPercentage: 20

```

*表 4-6.* `node-js-scale-hpa.yaml`

继续使用`kubectl create -f`命令创建这个。现在我们可以列出 hpas 并获得描述：

```
$ kubectl get hpa 

```

我们也可以使用`kubectl autoscale`命令在命令行中创建自动缩放。前面的 YAML 看起来像下面这样：

`$ kubectl autoscale rc/node-js-scale --min=1 --max=3 --cpu-percent=20`

这将显示一个具有目标 CPU 为 30%的`node-js-scale`复制控制器上的自动扩展器。此外，您将看到最小 pod 设置为 1，最大设置为 3：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_04_03.png)

没有负载的水平 Pod 自动缩放器

让我们还查询一下我们的 pod，看看现在有多少在运行：

```
$ kubectl get pods -l name=node-js-scale

```

由于我们的 HPA 显示 0% 利用率，因此我们只应该看到一个 `node-js-scale` pod，因此我们需要生成一些负载。我们将使用在许多容器演示中常见的流行应用程序 `boom`。以下清单将帮助我们创建连续的负载，直到我们可以达到自动缩放器的 CPU 阈值：

```
apiVersion: v1
kind: ReplicationController
metadata:
  name: boomload
spec:
  replicas: 1
  selector:
    app: loadgenerator
  template:
    metadata:
      labels:
        app: loadgenerator
    spec:
      containers:
      - image: williamyeh/boom
        name: boom
        command: ["/bin/sh","-c"]
        args: ["while true ; do boom http://node-js-scale/ -c 10 -n 100      
        ; sleep 1 ; done"]

```

*清单 4-7.* `boomload.yaml`

使用此清单的 `kubectl create -f` 命令，然后准备好开始监视我们之前使用的 `kubectl get hpa` 命令。

可能需要一些时间，但我们应该开始看到当前 CPU 利用率增加。一旦超过我们设置的 20% 阈值，自动缩放器就会启动：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_04_04.png)

负载开始后的水平 Pod 自动缩放

一旦我们看到这一点，我们可以再次运行 `kubectl get pod`，看到现在有几个 `node-js-scale` pod：

```
$ kubectl get pods -l name=node-js-scale

```

我们现在可以通过停止我们的负载生成 pod 来进行清理：

```
$ kubectl delete rc/boomload

```

现在如果我们观察 `hpa`，我们应该开始看到 CPU 使用率下降。可能需要几分钟，但最终，我们将会回到 0% 的 CPU 负载。

# 缩放集群

所有这些技术对于应用程序的扩展都非常棒，但是集群本身怎么样呢？在某些时候，您将会将节点填满，并且需要更多资源来为您的工作负载安排新的 pod。

# 自动缩放

当您创建集群时，您可以使用 `NUM_MINIONS` 环境变量自定义起始节点（minions）的数量。默认情况下，它设置为***4***。

此外，Kubernetes 团队已开始将自动缩放功能构建到集群本身中。目前，这是 GCE 和 GKE 上唯一支持的功能，但正在为其他提供者进行工作。此功能利用了 `KUBE_AUTOSCALER_MIN_NODES`、`KUBE_AUTOSCALER_MAX_NODES` 和 `KUBE_ENABLE_CLUSTER_AUTOSCALER` 环境变量。

以下示例显示了在运行 `kube-up.sh` 之前设置自动缩放环境变量的方法：

```
$ export NUM_MINIONS=5
$ export KUBE_AUTOSCALER_MIN_NODES=2
$ export KUBE_AUTOSCALER_MAX_NODES=5
$ export KUBE_ENABLE_CLUSTER_AUTOSCALER=true 

```

此外，请注意，在启动集群后更改这些内容将不会产生任何效果。您需要拆除集群并重新创建它。因此，本节将向您展示如何向现有集群添加节点而无需重新构建它。

一旦您以这些设置启动了集群，您的集群将根据集群中的计算资源使用情况自动按最小和最大限制进行缩放。

GKE 集群在启动时也支持自动缩放，当使用 alpha 特性时。前述示例将在命令行启动时使用诸如 `--enable-autoscaling --min-nodes=2 --max-nodes=5` 这样的标志。

# 在 GCE 上扩展集群规模

如果您希望扩展现有集群，我们可以通过几个步骤来实现。在 GCE 上手动扩展集群实际上非常简单。现有的管道使用了 GCE 中的托管实例组，这允许您通过实例模板轻松地向组中添加更多具有标准配置的机器。

你可以在 GCE 控制台中轻松看到这个模板。首先，打开控制台；默认情况下，这应该会打开你的默认项目控制台。如果你正在使用另一个项目来进行 Kubernetes 集群，请简单地从页面顶部的项目下拉菜单中选择它。

在侧边栏中，查看计算，然后是计算引擎，然后选择“实例模板”。你应该会看到一个名为 kubernetes-minion-template 的模板。请注意，如果你已经自定义了你的集群命名设置，名称可能会略有不同。点击该模板以查看详细信息。参考下面的截图：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_04_05-1.png)

用于从实例模板创建 GCE 实例组的模板

你会看到一些设置，但模板的核心部分在“自定义元数据”下。在这里，你将看到一些环境变量以及一个在创建新机器实例后运行的启动脚本。这些是允许我们创建新机器并自动将它们添加到可用集群节点的核心组件。

因为新机器的模板已经创建，所以在 GCE 中扩展我们的集群非常简单。一旦进入控制台的计算部分，只需在侧边栏的“实例模板”链接上方找到“实例组”即可。同样，你应该看到一个名为 kubernetes-minion-group 或类似的组。点击该组以查看详细信息，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_04_06.png)

用于从实例模板创建 GCE 实例组的模板

你会看到一个 CPU 指标图和三个在此列出的实例。默认情况下，集群会创建三个节点。我们可以通过点击页面顶部的“编辑组”按钮来修改这个组：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_04_07-2.png)

GCE 实例组编辑页面

你应该看到我们刚才审查的实例模板中选择了 kubernetes-minion-template。你还会看到一个自动缩放设置，默认为关闭状态，以及一个实例计数为`3`。简单地将此数值增加到`4`，然后点击“保存”。你将被带回到组详细信息页面，会看到一个显示待定更改的弹出对话框。

你还会在“实例组”编辑页面上看到一些自动修复属性。这会重新创建失败的实例，并允许你设置健康检查以及在执行操作之前的初始延迟时间。

几分钟后，你将在详细信息页面上看到一个新的实例。我们可以使用命令行中的`get nodes`命令来测试是否准备就绪：

```
$ kubectl get nodes

```

关于自动缩放和一般缩减的一些警告首先，如果我们重复之前的过程并将倒计时减少到四，GCE 会移除一个节点。但是，并不一定是你刚刚添加的节点。好消息是，Pod 将在剩余的节点上重新调度。然而，它只能重新调度可用资源的地方。如果你接近满负荷并关闭一个节点，那么有很大的机会一些 Pod 将无法重新调度。此外，这不是一个实时迁移，因此任何应用程序状态在过渡中都将丢失。底线是，在缩小规模或实施自动缩放方案之前，你应该仔细考虑其影响。

关于在 GCE 中的一般自动扩展的更多信息，请参考[`cloud.google.com/compute/docs/autoscaler/?hl=en_US#scaling_based_on_cpu_utilization`](https://cloud.google.com/compute/docs/autoscaler/?hl=en_US#scaling_based_on_cpu_utilization)链接。

# 在 AWS 上扩展集群

AWS 提供商代码也使得扩展集群变得非常容易。与 GCE 类似，AWS 设置使用自动扩展组来创建默认的四个从节点。将来，自动扩展组有望被集成到 Kubernetes 集群自动扩展功能中。目前，我们将通过手动设置来完成。

这也可以很容易地通过 CLI 或 Web 控制台进行修改。在控制台中，从 EC2 页面，只需转到左侧菜单底部的 Auto Scaling Groups 部分。你应该会看到一个类似于 kubernetes-minion-group 的名称。选择此组，你将会看到如下屏幕截图所示的详细信息：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_04_08.png)

Kubernetes minion autoscaling details

我们可以通过点击**编辑**来轻松扩展这个组。然后，将所需、最小和最大值更改为`5`，然后点击保存。几分钟后，你将会有第五个节点可用。你可以再次使用`get nodes`命令来检查这一点。

缩小规模的过程相同，但请记住我们在前一节*在 GCE 上扩展集群*中讨论了相同的考虑因素。工作负载可能会被放弃，或者至少会意外重新启动。

# 手动扩展

对于其他提供商，创建新的从节点可能不是一个自动化的过程。根据你的提供商，你需要执行各种手动步骤。查看`cluster`目录中的特定于提供商的脚本可能会有所帮助。

# 总结

现在我们对 Kubernetes 中应用程序扩展的基础有了更多的了解。我们还研究了内置功能以便进行滚动更新以及一个用于测试和缓慢集成更新的手动流程。我们看了一下如何扩展底层集群的节点，并增加我们 Kubernetes 资源的总体容量。最后，我们探讨了一些新的自动扩展概念，包括集群和应用程序本身。

在下一章中，我们将探讨利用新的**deployments**资源类型来扩展和更新应用程序的最新技术，以及在 Kubernetes 上可以运行的其他工作负载类型。


# 第五章：部署、作业和 DaemonSets

本章将介绍 Kubernetes 支持的各种工作负载类型。我们将介绍用于经常更新和长时间运行的应用程序的**部署**。我们还将重新审视使用部署进行应用程序更新和渐进式部署的主题。此外，我们还将查看用于短暂任务的**作业**。最后，我们将查看**DaemonSets**，它允许程序在 Kubernetes 集群中的每个节点上运行。

本章将讨论以下内容：

+   部署

+   使用部署进行应用程序扩展

+   使用部署进行应用程序更新

+   作业

+   DaemonSets

# 部署

在上一章中，我们探讨了使用旧的滚动更新方法进行应用程序更新的一些核心概念。从版本 1.2 开始，Kubernetes 添加了 Deployment 构造，它改进了滚动更新和 Replication Controllers 的基本机制。顾名思义，它使我们可以更精细地控制代码部署本身。部署允许我们暂停和恢复应用程序的部署。此外，它保留了过去部署的历史，并允许用户轻松回滚到以前的版本。

在接下来的*列表 5-1*中，我们可以看到该定义与 Replication Controller 非常相似。主要区别在于，现在我们可以对部署对象进行更改和更新，并让 Kubernetes 管理更新底层的 pod 和副本：

```
apiVersion: extensions/v1beta1
kind: Deployment
metadata:
  name: node-js-deploy
labels:
    name: node-js-deploy
spec:
    replicas: 1
   template:
     metadata:
       labels:
         name: node-js-deploy
     spec:
       containers:
       - name: node-js-deploy
         image: jonbaier/pod-scaling:0.1
         ports:
         - containerPort: 80

```

*列表 5-1*：`node-js-deploy.yaml`

我们可以运行熟悉的`create`命令，带上可选的`--record`标志，以便将部署的创建记录在发布历史中。否则，我们将只看到发布历史中的后续更改：

```
$ kubectl create -f node-js-deploy.yaml --record 

```

如果在您的集群上未启用此 beta 类型，您可能需要添加`--validate=false`。

我们应该会看到部署成功创建的消息。几分钟后，它将完成创建我们的 pod，我们可以用`get pods`命令自行检查。我们添加了`-l`标志，只看到与此部署相关的 pod：

```
$ kubectl get pods -l name=node-js-deploy

```

我们创建了一个服务，就像我们之前使用 Replication Controllers 那样。下面是我们刚刚创建的部署的`Service`定义。我们会注意到，它几乎与我们以前创建的服务完全相同：

```
apiVersion: v1
kind: Service
metadata:
  name: node-js-deploy
  labels:
    name: node-js-deploy
spec:
  type: LoadBalancer
  ports:
  - port: 80
  sessionAffinity: ClientIP
  selector:
    name: node-js-deploy

```

*列表 5-2.* `node-js-deploy-service.yaml`

使用 `kubectl` 创建此服务后，您将能够通过服务 IP 或者如果您在此命名空间的 pod 内部，则通过服务名称访问部署的 pod。

# 扩展

`scale` 命令的使用方式与我们的 Replication Controller 中的一样。要扩展，我们只需使用部署名称并指定新的副本数量，如下所示：

```
$ kubectl scale deployment node-js-deploy --replicas 3

```

如果一切顺利，我们将只会在终端窗口的输出中看到关于部署扩展的消息。我们可以再次使用先前的`get pods`命令来检查正在运行的 pod 数量。

# 更新和部署

部署允许以几种不同的方式进行更新。首先，有`kubectl set`命令，它允许我们在不手动重新部署的情况下更改部署配置。目前，它只允许更新镜像，但随着我们的应用程序或容器镜像的新版本被处理，我们将经常需要这样做。

让我们从前一节的部署中进行查看。我们现在应该有三个副本正在运行。通过运行带有我们部署筛选器的`get pods`命令来验证这一点：

```
$ kubectl get pods -l name=node-js-deploy

```

我们应该看到三个与以下屏幕截图中列出的类似的 pod：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_05_01-1.png)

部署 Pod 列表

从我们的设置中选择一个 pod，将其替换到以下命令中的位置，其中写着`{POD_NAME_FROM_YOUR_LISTING}`，然后运行该命令：

```
$ kubectl describe pod/{POD_NAME_FROM_YOUR_LISTING} | grep Image:

```

我们应该看到一个如下图所示的输出，其中包含当前镜像版本`0.1`：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_05_02-1.png)

当前 Pod 图像

现在我们知道了我们当前的部署正在运行什么，让我们尝试更新到下一个版本。这可以通过使用`kubectl set`命令并指定新版本轻松实现，如下所示：

```
$ kubectl set image deployment/node-js-deploy node-js-deploy=jonbaier/pod-scaling:0.2

```

如果一切顺利，我们应该在屏幕上看到显示`deployment "node-js-deploy" image updated`的文本。

我们可以使用以下`rollout status`命令再次检查状态：

```
$ kubectl rollout status deployment/node-js-deploy

```

我们应该看到一些关于成功部署的文本。如果您看到任何关于等待部署完成的文本，您可能需要等待片刻，或者可以检查日志以查看问题。

完成后，再次运行`get pods`命令，就像之前一样。这次我们将看到新列出的 pods：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_05_03-1.png)

更新后的部署 Pod 列表

再次将您的一个 pod 名称插入我们之前运行的`describe`命令中。这次我们应该看到镜像已经更新为`0.2`。

在幕后发生的事情是 Kubernetes 为我们*部署*了一个新版本。它基本上创建了一个具有新版本的新副本集。一旦这个 pod 在线并且健康，它就会杀死一个旧版本。它继续这个行为，扩展新版本并缩减旧版本，直到只剩下新的 pods。

以下图示描述了您的工作流程供参考：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_05_04.png)

部署生命周期

值得注意的是，回滚定义允许我们在部署定义中控制 pod 替换方法。有一个`strategy.type`字段，默认为`RollingUpdate`和前面的行为。可选地，我们也可以指定`Recreate`作为替换策略，它将首先杀死所有旧的 pods，然后创建新版本。

# 历史和回滚

rollout api 的一个有用功能是跟踪部署历史。在检查历史之前，让我们再次更新一次。再次运行`kubectl set`命令，并指定版本`0.3`：

```
$ kubectl set image deployment/node-js-deploy node-js-deploy=jonbaier/pod-scaling:0.3

```

我们将再次看到屏幕上显示`deployment "node-js-deploy" image updated`的文本。现在再次运行`get pods`命令：

```
$ kubectl get pods -l name=node-js-deploy

```

让我们也查看一下我们的部署历史记录。运行`rollout history`命令：

```
$ kubectl rollout history deployment/node-js-deploy 

```

我们应该看到类似下面的输出：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_05_05.png)

滚动历史

如我们所见，历史记录显示了初始部署创建、我们第一次更新到`0.2`，然后最终更新到`0.3`。除了状态和历史记录外，`rollout`命令还支持`pause`、`resume`和`undo`子命令。`rollout pause`命令允许我们在滚动仍在进行时暂停命令。这对故障排除很有用，也对金丝雀式启动很有帮助，我们希望在向整个用户群推出新版本之前对新版本进行最终测试。当我们准备继续滚动时，我们只需使用`rollout resume`命令。

但是如果出现问题怎么办？这就是`rollout undo`命令和滚动历史本身真正方便的地方。让我们模拟这种情况，尝试更新到尚未可用的版本的 pod。我们将图像设置为版本`42.0`，该版本不存在：

```
$ kubectl set image deployment/node-js-deploy node-js-deploy=jonbaier/pod-scaling:42.0

```

我们应该仍然看到屏幕上显示`deployment "node-js-deploy" image updated`的文本。但是如果我们检查状态，会发现它仍在等待：

```
$ kubectl rollout status deployment/node-js-deploy

```

我们可以按下*Ctrl* + *C*来终止`status`命令，然后再次运行`get pods`命令：

```
$ kubectl get pods -l name=node-js-deploy

```

我们现在应该看到一个`ErrImagePull`，如下面的截图：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_05_06.png)

图像拉取错误

正如我们预期的那样，它不能拉取图像的 42.0 版本，因为该版本不存在。此外，如果我们在集群上资源不足或者达到了为我们命名空间设置的限制，我们可能还会在部署方面遇到问题。此外，部署可能因许多应用程序相关原因而失败，例如健康检查失败、权限问题和应用程序错误等。

每当发生无法滚动部署的失败时，我们可以通过使用`rollout undo`命令轻松回滚到先前的版本。此命令将把我们的部署退回到之前的版本：

```
$ kubectl rollout undo deployment/node-js-deploy

```

之后，我们可以再次运行`rollout status`命令，应该会看到一切都成功滚动了。再次运行`rollout history`命令，我们会看到我们尝试滚动到版本`42.0`，以及回滚到`0.3`的情况：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_05_07.png)

回滚后的滚动历史

在运行撤消时，我们还可以指定`--to-revision`标志以回滚到特定版本。在我们的滚动成功后，但我们后来发现有逻辑错误时，这可能很方便。

# 自动缩放

正如你所看到的，部署是对复制控制器的重大改进，使我们能够无缝更新我们的应用程序，同时与 Kubernetes 的其他资源以类似的方式集成。

在前一章中我们看到的另一个领域，也支持部署，就是**水平 Pod 自动缩放器**（**HPAs**）。正如你可能猜到的那样，这也与部署完美集成。我们将快速重制前一章的 HPAs，这次使用我们到目前为止创建的部署：

```
apiVersion: autoscaling/v1
kind: HorizontalPodAutoscaler
metadata:
  name: node-js-deploy
spec:
  minReplicas: 3
  maxReplicas: 6
  scaleTargetRef:
    apiVersion: v1
    kind: Deployment
    name: node-js-deploy
  targetCPUUtilizationPercentage: 10

```

*Listing 5-3.* `node-js-deploy-hpa.yaml`

我们已经将 CPU 阈值降低到 `10%` 并将我们的最小和最大 pod 更改为分别是 `3` 和 `6`。使用我们信赖的 `kubectl create -f` 命令创建前述 HPA。完成后，我们可以使用 `kubectl get hpa` 命令检查其是否可用：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_05_08.png)

水平 Pod 自动缩放器

我们还可以通过 `kubectl get deploy` 命令检查我们只运行了 `3` 个 pod。现在让我们添加一些负载以触发自动扩展器：

```
apiVersion: extensions/v1beta1
kind: Deployment
metadata:
  name: boomload-deploy
spec:
  replicas: 1
  template:
    metadata:
      labels:
        app: loadgenerator-deploy
    spec:
      containers:
      - image: williamyeh/boom
        name: boom-deploy
        command: ["/bin/sh","-c"]
        args: ["while true ; do boom http://node-js-deploy/ -c 10 -n
        100 ; sleep 1 ;     
        done"]

```

*Listing 5-4.* `boomload-deploy.yaml`

像往常一样创建 *listing 5-4*。现在使用交替的 `kubectl get hpa` 和 `kubectl get deploy` 命令监视 HPA。几分钟后，我们应该看到负载跳到 `10%` 以上。再过一会儿，我们还应该看到 pod 数量增加到 `6` 个副本：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_05_09.png)

HPA 增加和 Pod 扩容

同样，我们可以通过删除我们的负载生成 pod 并等待片刻来清理这一点：

```
$ kubectl delete deploy boomload-deploy

```

同样，如果我们观察 HPA，我们将开始看到 CPU 使用率下降。几分钟后，我们的 CPU 负载将降至 `0%`，然后 Deployment 将缩减到 `3` 个副本。

# 工作

部署和复制控制器是确保长时间运行的应用程序始终处于运行状态并能够容忍各种基础设施故障的好方法。然而，有一些情况下这并不能解决 —— 特别是短期运行的、*仅运行一次*的任务以及定期计划的任务。在这两种情况下，我们需要任务运行直到完成，然后在下一个计划的时间间隔开始终止并重新启动。

为了解决这种类型的工作负载，Kubernetes 添加了一个 **批处理 API**，其中包括 **Job** 类型。此类型将创建 1 到 n 个 pod，并确保它们全部成功完成退出。根据 `restartPolicy`，我们可以允许 pod 简单地失败而不进行重试（`restartPolicy: Never`），或者在 pod 退出而没有成功完成时进行重试（`restartPolicy: OnFailure`）。在这个例子中，我们将使用后者的技术：

```
apiVersion: batch/v1
kind: Job
metadata:
  name: long-task
spec:
  template:
    metadata:
      name: long-task
    spec:
      containers:
      - name: long-task
        image: docker/whalesay
        command: ["cowsay", "Finishing that task in a jiffy"]
      restartPolicy: OnFailure

```

*Listing 5-5*: `longtask.yaml`

让我们用以下命令运行：

```
$ kubectl create -f longtask.yaml

```

如果一切顺利，您将在屏幕上看到打印出 `job "long-task" created`。

这告诉我们该任务已创建，但并不告诉我们是否成功完成了。要检查这一点，我们需要使用以下命令查询任务状态：

```
$ kubectl describe jobs/long-task

```

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_05_10.png)

任务状态

您应该看到我们有`1`个成功完成的任务，在`Events`日志中，有一个 SuccessfulCreate 消息。如果我们使用`kubectl get pods`命令，我们将看不到我们的**long-task** pods 在列表中，但是如果列表底部指出有未显示的已完成作业，则可能会注意到该消息。我们需要再次使用`-a`或`--show-all`标志运行命令，以查看**long-task** pod 和已完成的作业状态。

让我们深入一点，以证明工作已成功完成。我们可以使用`logs`命令查看 pod 的日志。但是，我们也可以使用 UI 来完成这个任务。打开浏览器，转到以下 UI 网址：`https://**<your master ip>**/ui/`

点击*Jobs*，然后从列表中选择*long-task*，以便我们可以查看详细信息。然后，在 Pods 部分，单击那里列出的 pod。这将给我们提供 Pod 详细信息页面。在详细信息底部，单击*查看日志*，我们将看到日志输出：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_05_11.png)

作业日志

如您在上图中所见，whalesay 容器已经完成了 ASCII 艺术，并且我们自定义的消息来自示例中的运行时参数。

# 其他类型的作业

虽然此示例提供了关于短期运行作业的基本介绍，但它仅涉及一次性任务的用例。实际上，批处理工作通常是**并行**进行的，或者作为定期发生的任务的一部分。

# 并行作业

使用**并行**作业，我们可能正在从正在进行的队列中获取任务，或者仅运行一组不相互依赖的任务。在从队列中获取作业的情况下，我们的应用程序必须了解依赖关系，并具有逻辑来决定如何处理任务以及下一步要处理的内容。Kubernetes 只是在调度这些作业。

您可以从 Kubernetes 文档和批处理 API 参考中了解有关并行作业的更多信息（您可以在本章末尾的*参考*部分中查看有关此的更多详细信息）。

# 计划任务

对于需要定期运行的任务，Kubernetes 还发布了 alpha 版的`CronJob`类型。正如我们所期望的，此类作业使用底层的 cron 格式来指定我们希望运行的任务的时间表。默认情况下，我们的集群不会启用 alpha 批处理功能，但是我们可以查看一个示例`CronJob`列表，以了解这些类型的工作负载将如何继续工作：

```
apiVersion: batch/v2alpha1
kind: CronJob
metadata:
  name: long-task-cron
spec:
  schedule: "15 10 * * 6"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: long-task-cron
            image: docker/whalesay
            command: ["cowsay", "Developers! Developers! Developers!
          \n\n Saturday task    
            complete!"]
          restartPolicy: OnFailure

```

*清单 5-6.*`longtask-cron.yaml`

如您所见，计划部分反映了具有以下格式的 crontab：

**分钟 小时 月中日 月份 周中的日**

在本示例中，`15 10 * * 6`创建了一个任务，将在每个`星期六`的上午 10:15 运行。

# 守护进程集

虽然 Replication Controllers 和 Deployments 在确保特定数量的应用程序实例正在运行方面表现出色，但它们是在最佳适合的情况下进行的。这意味着调度器会寻找满足资源需求（可用 CPU、特定存储卷等）的节点，并尝试在节点和区域之间分配。

这对于创建高可用和容错应用程序非常有效，但是对于我们需要在集群的每个节点上运行代理的情况怎么办？虽然默认的分布确实尝试使用不同的节点，但它不保证每个节点都有副本，实际上只会填充与 RC 或 Deployment 规范中指定的数量相当的节点。

为了减轻这一负担，Kubernetes 引入了`DaemonSet`，它简单地定义了一个 pod 在集群的每个节点或定义的一部分节点上运行。这对于许多生产相关的活动非常有用，例如监控和日志代理、安全代理和文件系统守护程序。

实际上，Kubernetes 已经在一些核心系统组件中使用了这种能力。如果我们回顾一下第一章，*Kubernetes 简介*，我们会看到一个`node-problem-detector`在节点上运行。这个 pod 实际上是作为`DaemonSet`在集群的每个节点上运行的。我们可以通过在`kube-system`命名空间中查询 DaemonSets 来看到这一点：

```
$ kubectl get ds --namespace=kube-system

```

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_05_12.png)

kube-system DaemonSets

你可以在以下清单中找到关于`node-problem-detector`以及`yaml`的更多信息：[`kubernetes.io/docs/admin/node-problem/#node-problem-detector`](http://kubernetes.io/docs/admin/node-problem/#node-problem-detector)：

```
apiVersion: extensions/v1beta1
kind: DaemonSet
metadata:
  name: node-problem-detector-v0.1
  namespace: kube-system
  labels:
    k8s-app: node-problem-detector
    version: v0.1
    kubernetes.io/cluster-service: "true"
spec:
  template:
    metadata:
      labels:
        k8s-app: node-problem-detector
        version: v0.1
        kubernetes.io/cluster-service: "true"
    spec:
      hostNetwork: true
      containers:
      - name: node-problem-detector
        image: gcr.io/google_containers/node-problem-detector:v0.1
        securityContext:
          privileged: true
        resources:
          limits:
            cpu: "200m"
            memory: "100Mi"
          requests:
            cpu: "20m"
            memory: "20Mi"
        volumeMounts:
        - name: log
          mountPath: /log
          readOnly: true
        volumes:
        - name: log
          hostPath:
            path: /var/log/

```

*清单 5-7\. node-problem-detector 定义*

# 节点选择

正如前面提到的，我们也可以将 DaemonSets 安排在节点的子集上运行。这可以通过称为**nodeSelectors**的东西来实现。它们允许我们通过查找特定的标签和元数据来限制 pod 运行的节点。它们只是在每个节点的标签上匹配键值对。我们可以添加自己的标签或使用默认分配的标签。

默认标签列在以下表中：

| **默认节点标签** | **描述** |
| --- | --- |
| `kubernetes.io/hostname` | 这显示了底层实例或机器的主机名 |
| `beta.kubernetes.io/os` | 这显示了通过 Go 语言报告的底层操作系统。 |
| `beta.kubernetes.io/arch` | 这显示了通过 Go 语言报告的底层处理器架构。 |
| `beta.kubernetes.io/instance-type` | (**仅限云**) 底层云提供商的实例类型 |
| `failure-domain.beta.kubernetes.io/region` | (**仅限云**) 底层云提供商的区域 |
| `failure-domain.beta.kubernetes.io/zone` | (**仅限云**) 底层云提供商的容错区域 |

*表 5.1 - Kubernetes 默认节点标签*

我们不仅限于 DaemonSets，因为 nodeSelectors 实际上也适用于 Pod 定义，并且不限于 DaemonSets。让我们仔细看看作业示例（对我们之前的长任务示例进行了轻微修改）。

首先，我们可以在节点上看到这些。让我们获取我们节点的名称：

```
$ kubectl get nodes

```

使用前一个命令的输出中的名称并将其插入到这个命令中：

```
$ kubectl describe node <node-name>

```

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_05_13.png)

来自节点描述的摘录

现在让我们给这个节点添加一个昵称标签：

```
$ kubectl label nodes <node-name> nodenickname=trusty-steve

```

如果我们再次运行`kubectl describe node`命令，我们将看到此标签列在默认值旁边。现在我们可以调度工作负载并指定这个特定的节点。以下是我们早期的长时间运行任务的修改版本，添加了`nodeSelector`：

```
apiVersion: batch/v1
kind: Job
metadata:
  name: long-task-ns
spec:
  template:
    metadata:
      name: long-task-ns
    spec:
      containers:
      - name: long-task-ns
        image: docker/whalesay
        command: ["cowsay", "Finishing that task in a jiffy"]
      restartPolicy: OnFailure
      nodeSelector:
        nodenickname: trusty-steve

```

*图 5-8.* `longtask-nodeselector.yaml`

用 `kubectl create -f` 从此列表创建作业。

一旦成功，它将根据前述规范创建一个 pod。由于我们已经定义了`nodeSelector`，它将尝试在具有匹配标签的节点上运行 pod，并在找不到候选节点时失败。我们可以通过在查询中指定作业名称来找到该 pod，如下所示：

```
$ kubectl get pods -a -l job-name=long-task-ns

```

我们使用`-a`标志来显示所有 pod。作业的生命周期很短，一旦进入完成状态，它们就不会出现在基本的`kubectl get pods`查询中。我们还使用`-l`标志来指定具有`job-name=long-task-ns`标签的 pod。这将给我们提供 pod 名称，我们可以将其推入以下命令：

```
$ kubectl describe pod <Pod-Name-For-Job> | grep Node: 

```

结果应该显示此 pod 所在节点的名称。如果一切顺利，它应该与我们之前用`trusty-steve`标签标记的节点匹配。

# 概要

现在你应该对 Kubernetes 中的核心构造有一个良好的基础。我们探讨了新的 Deployment 抽象及其如何改进基本的 Replication Controller，从而实现了平滑的更新和与服务及自动缩放的坚实集成。我们还查看了作业和 DaemonSets 中的其他类型的工作负载。你学会了如何运行短期或批处理任务，以及如何在我们的集群中的每个节点上运行代理。最后，我们简要地看了一下节点选择以及如何用它来过滤集群中用于我们工作负载的节点。

我们将在本章学到的内容的基础上继续，然后在下一章中查看**有状态**应用程序，探索关键的应用程序组件和数据本身。

# 参考资料

1.  [`kubernetes.io/docs/user-guide/jobs/#parallel-jobs`](https://kubernetes.io/docs/user-guide/jobs/#parallel-jobs)


# 第六章：存储和运行有状态应用程序

在本章中，我们将讨论如何附加持久卷并为有状态应用程序和数据创建存储。我们将详细介绍存储方面的问题以及如何在容器的生命周期内跨 pod 持久化数据。我们将探索**PersistentVolumes**类型以及**PersistentVolumeClaim**。最后，我们将看一下版本 1.5 中新发布的**StatefulSets**。

本章将讨论以下主题：

+   持久存储

+   PersistentVolumes

+   PersistentVolumeClaims

+   StorageClasses

+   StatefulSets

# 持久存储

到目前为止，我们只处理了可以随意启动和停止的工作负载，没有任何问题。然而，现实世界的应用程序通常具有状态，并记录我们希望（甚至坚持）不要丢失的数据。容器本身的瞬时性质可能是一个很大的挑战。如果您还记得我们在第一章 *Kubernetes 简介*中对分层文件系统的讨论，顶层是可写的。（它也是糖霜，非常美味。）但是，当容器死亡时，数据也会随之而去。 Kubernetes 重新启动的已崩溃容器也是如此。

这就是**卷**或磁盘发挥作用的地方。一个存在于容器之外的卷使我们能够在容器中断期间保存重要数据。此外，如果我们在 pod 级别有一个卷，数据可以在同一应用程序堆栈中的多个容器之间以及同一 pod 内部共享。

Docker 本身对卷有一些支持，但 Kubernetes 为我们提供了持久存储，可以持续存在于单个容器的生命周期之外。这些卷与 pod 相关联，并与这些 pod 一起生存和死亡。此外，一个 pod 可以有多个来自各种来源的卷。让我们看一下其中一些来源。

# 临时磁盘

在容器崩溃和 pod 内数据共享之间实现改进的持久性的最简单方法之一是使用`emptydir`卷。此卷类型可与节点机器本身的存储卷或可选的 RAM 磁盘一起使用，以实现更高的性能。

再次改进我们的持久性超出一个单独的容器，但是当一个 pod 被移除时，数据将会丢失。机器重启也会清除 RAM 类型磁盘中的任何数据。有时我们只需要一些共享的临时空间或者有处理数据并在死亡之前将其传递给另一个容器的容器。无论情况如何，以下是使用这个临时磁盘和 RAM 支持选项的快速示例。

打开您喜欢的编辑器，并创建一个类似以下*Listing 6-1*的文件：

```
apiVersion: v1 
kind: Pod 
metadata: 
  name: memory-pd 
spec: 
  containers: 
  - image: nginx:latest 
    ports: 
    - containerPort: 80 
    name: memory-pd 
    volumeMounts: 
    - mountPath: /memory-pd 
      name: memory-volume 
  volumes: 
  - name: memory-volume 
    emptyDir: 
      medium: Memory 

```

*Listing 6-1*: `storage-memory.yaml`

前面的例子现在可能已经是家常便饭了，但我们将再次发出一个`create`命令，然后是一个`exec`命令，以查看容器中的文件夹：

```
$ kubectl create -f storage-memory.yaml
$ kubectl exec memory-pd -- ls -lh | grep memory-pd 

```

这将为我们在容器本身中提供一个 bash shell。`ls` 命令显示我们在顶级看到一个 `memory-pd` 文件夹。我们使用 `grep` 来过滤输出，但是你可以不用 `| grep memory-pd` 来运行命令以查看所有文件夹：

![图片](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_06_01.png)

容器内的临时存储

再次说明，这个文件夹是非常临时的，因为所有内容都存储在节点（minion）的 RAM 中。当节点重新启动时，所有文件都将被删除。接下来我们将看一个更加永久的例子。

# 云存储卷

许多公司已经在公共云中运行了大量基础架构。幸运的是，Kubernetes 原生支持两个最受欢迎提供者提供的持久存储。

# GCE 持久磁盘

我们从 GCE 网站中获得了以下内容：

<q>Google Persistent Disk 是 Google 云平台的持久且高性能的块存储。持久磁盘提供 SSD 和 HDD 存储，可附加到运行在 Google Compute Engine 或 Google Container Engine 中的实例。存储卷可以透明地调整大小，快速备份，并具有支持同时读取的能力。</q>（你可以在本章末尾的*参考*部分中查看关于此的更多详细信息）

让我们创建一个新的 **GCE 持久磁盘**。

1.  从控制台中，在 Compute Engine 中，转到“磁盘”。在这个新屏幕上，点击“创建磁盘”按钮。我们将看到一个类似于下图的屏幕。

1.  为此卷选择一个名称并简要描述它。确保区域与集群中的节点相同。GCE PD 只能附加到相同区域中的机器上。

1.  在“名称”字段中输入 `mysite-volume-1`。选择与集群中至少一个节点匹配的区域。选择“无”（空白磁盘）作为“源类型”，并在“大小（GB）”中输入 `10`（10 GB）作为值。最后，点击“创建”：

![图片](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_06_02.png)

GCE 新持久磁盘

在 GCE 上，持久磁盘的好处是它们允许挂载到多台机器（在我们的情况下是节点）。然而，当挂载到多台机器时，卷必须处于只读模式。因此，让我们首先将其挂载到单个 Pod 上，以便我们可以创建一些文件。使用 *列表 6-2*：`storage-gce.yaml` 如下创建一个将以读/写模式挂载磁盘的 Pod：

```
apiVersion: v1 
kind: Pod 
metadata: 
  name: test-gce 
spec: 
  containers: 
  - image: nginx:latest 
    ports: 
    - containerPort: 80 
    name: test-gce 
    volumeMounts: 
    - mountPath: /usr/share/nginx/html 
      name: gce-pd 
  volumes: 
  - name: gce-pd 
    gcePersistentDisk: 
      pdName: mysite-volume-1 
      fsType: ext4 

```

*列表 6-2*：`storage-gce.yaml`

首先，让我们发出一个 `create` 命令，然后是一个 `describe` 命令，以找出它正在哪个节点上运行：

```
$ kubectl create -f storage-gce.yaml 
$ kubectl describe pod/test-gce

```

注意节点并保存该 Pod 的 IP 地址以备后用。然后，打开一个 SSH 会话到该节点：

![图片](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_06_03-1.png)

具有持久磁盘的 Pod 描述

输入以下命令：

```
$ gcloud compute --project "<Your project ID>" ssh --zone "<your gce zone>" "<Node running test-gce pod>" 

```

由于我们已经从正在运行的容器内部查看了卷，所以这次让我们直接从节点（minion）本身访问它。我们将运行一个 `df` 命令来查看它被挂载在哪里，但我们需要先切换到 root 用户：

```
$ sudo su -
$ df -h | grep mysite-volume-1 

```

正如你所见，GCE 卷直接挂载到节点本身。我们可以使用前面`df`命令的输出中列出的挂载路径。现在使用`cd`切换到该文件夹。然后，使用你喜欢的编辑器创建一个名为`index.html`的新文件：

```
$ cd /var/lib/kubelet/plugins/kubernetes.io/gce-pd/mounts/mysite-volume-1
$ vi index.html 

```

输入一条简短的消息，比如`Hello from my GCE PD!`。现在保存文件并退出编辑器。如果你还记得 *列表 6-2* 中提到的，PD 是直接挂载到 Nginx HTML 目录的。所以，让我们在节点上仍然保持 SSH 会话的情况下测试一下。对我们之前记下的 pod IP 执行一个简单的`curl`命令：

```
$ curl <Pod IP from Describe> 

```

你应该能看到来自我的 GCE PD 的消息，或者你在`index.html`文件中保存的任何消息。在真实的场景中，我们可以为整个网站或任何其他中央存储使用这个卷。让我们来看看运行一组负载均衡的 Web 服务器，它们都指向同一个卷。

首先，使用两个`exit`命令离开 SSH 会话。在继续之前，我们需要删除`test-gce` pod，这样卷就可以被挂载为只读在多个节点上：

```
$ kubectl delete pod/test-gce 

```

现在我们可以创建一个 RC，它将运行三个 Web 服务器，所有服务器都挂载相同的持久磁盘，如下所示：

```
apiVersion: v1 
kind: ReplicationController 
metadata: 
  name: http-pd 
  labels: 
    name: http-pd 
spec: 
  replicas: 3 
  selector: 
    name: http-pd 
  template: 
    metadata: 
      name: http-pd 
      labels:
        name: http-pd
    spec: 
      containers: 
      - image: nginx:latest 
        ports: 
        - containerPort: 80 
        name: http-pd 
        volumeMounts: 
        - mountPath: /usr/share/nginx/html 
          name: gce-pd 
      volumes: 
      - name: gce-pd 
        gcePersistentDisk: 
          pdName: mysite-volume-1 
          fsType: ext4 
          readOnly: true 

```

*列表 6-3*：`http-pd-controller.yaml`

我们还要创建一个外部服务，这样我们就可以从集群外部看到它：

```
apiVersion: v1 
kind: Service 
metadata: 
  name: http-pd 
  labels: 
    name: http-pd 
spec: 
  type: LoadBalancer 
  ports: 
  - name: http 
    protocol: TCP 
    port: 80 
  selector: 
    name: http-pd 

```

*列表 6-4*：`http-pd-service.yaml`

现在创建这两个资源。等待一段时间以分配外部 IP。之后，`describe`命令将给我们一个可以在浏览器中使用的 IP：

```
$ kubectl describe service/http-pd 

```

以下屏幕截图是上述命令的结果：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_06_04.png)

K8s 服务与 GCE PD 跨三个 pod 共享

如果你还没有看到`LoadBalancer Ingress`字段，那可能需要更多时间来分配。将`LoadBalancer Ingress`中的 IP 地址键入到浏览器中，你应该能看到我们之前输入的熟悉的`index.html`文件显示出来的文本！

# AWS 弹性块存储

K8s 还支持 AWS **弹性块存储**（**EBS**）卷。与 GCE PD 相同，EBS 卷需要附加到在相同可用性区域运行的实例上。进一步的限制是，EBS 只能一次挂载到单个实例上。

为了简洁起见，我们不会演示 AWS 示例，但包含了一个示例 YAML 文件以帮助你开始。同样，记得在 pod 之前创建 EBS 卷：

```
apiVersion: v1 
kind: Pod 
metadata: 
  name: test-aws 
spec: 
  containers: 
  - image: nginx:latest 
    ports: 
    - containerPort: 80 
    name: test-aws 
    volumeMounts: 
    - mountPath: /usr/share/nginx/html 
      name: aws-pd 
  volumes: 
  - name: aws-pd 
    awsElasticBlockStore: 
      volumeID: aws://<availability-zone>/<volume-id> 
      fsType: ext4 

```

*列表 6-5*：`storage-aws.yaml`

# 其他存储选项

Kubernetes 支持各种其他类型的存储卷。完整列表可以在这里找到：[`kubernetes.io/v1.0/docs/user-guide/volumes.html#types-of-volumes`](http://kubernetes.io/v1.0/docs/user-guide/volumes.html#types-of-volumes)。 [](http://kubernetes.io/v1.0/docs/user-guide/volumes.html#types-of-volumes)

这里有一些可能特别感兴趣的：

+   `nfs`：这种类型允许我们挂载**网络文件共享**（**NFS**），对于持久化数据并在基础设施中共享它非常有用

+   `gitrepo`：你可能已经猜到了，这个选项将一个 Git 仓库克隆到一个新的空文件夹中。

# 持久卷和存储类

到目前为止，我们已经看到了在我们的 Pod 定义中直接供应存储的例子。如果您完全控制您的集群和基础设施，这种方法运行得很好，但在更大规模上，应用程序所有者将希望使用单独管理的存储。通常，一个中央 IT 团队或云提供商本身将负责管理存储的细节，并让应用程序所有者担心他们的主要关注点，即应用程序本身。

为了适应这一点，我们需要一种方法，让应用程序指定和请求存储而不用担心如何提供存储。这就是`PersistentVolumes`和`PersistentVolumeClaims`发挥作用的地方。`PersistentVolumes`类似于我们之前创建的`volumes`，但是它们由集群管理员提供，并且不依赖于特定的 Pod。然后，Pod 可以使用`PersistentVolumeClaims`声明来声明此卷。

`PersistentVolumeClaims`允许我们指定所需存储的细节。我们可以定义存储量以及访问类型，如`ReadWriteOnce`（一个节点读写）、`ReadOnlyMany`（多个节点只读）和`ReadWriteMany`（多个节点读写）。当然，支持哪些模式取决于支持的后端存储提供者。例如，我们在 AWS EBS 示例中看到，挂载到多个节点不是一个选项。

此外，Kubernetes 提供了另外两种指定特定分组或存储卷类型的方法。第一种是使用选择器，就像我们之前为 Pod 选择所见的那样。在这里，标签可以应用于存储卷，然后声明可以引用这些标签以进一步过滤它们所提供的卷。其次，Kubernetes 具有 StorageClass 的概念，允许我们指定一个存储提供程序和用于其提供的卷类型的参数。

我们将在下一节深入研究 StorageClasses，但这里有一个`PersistentVolumeClaims`的快速示例，以便说明目的。您可以在注释中看到我们请求以`ReadWriteOnce`模式和`solidstate`存储类的`1Gi`存储，并带有`aws-storage`标签。

```
kind: PersistentVolumeClaim
apiVersion: v1
metadata:
  name: demo-claim
  annotations:
    volume.beta.kubernetes.io/storage-class: "solidstate"
spec:
  accessModes:
  - ReadWriteOnce
  resources:
    requests:
      storage: 1Gi
  selector:
    matchLabels:
      release: "aws-storage"

```

*清单 6-6：* `pvc-example.yaml`

# 有状态副本集

**StatefulSets**的目的是为具有状态数据的应用程序部署提供一些一致性和可预测性。到目前为止，我们已经将应用程序部署到集群中，定义了对所需资源（如计算和存储）的松散要求。集群已经在满足这些要求的任何节点上安排了我们的工作负载。虽然我们可以使用其中一些约束以更可预测的方式部署，但如果我们有一个构造来帮助我们提供这种一致性将会很有帮助。

当我们完成此书稿时，StatefulSets 已经设置为 GA 版本 1.6。它们之前是 beta 版本 1.5，之前称为 PetSets（1.3 和 1.4 中的 alpha 版本）。

这就是 StatefulSets 的用武之地。StatefulSets 首先为我们提供了有序和可靠的命名，用于网络访问和存储索赔。这些 pod 本身的命名采用以下约定，其中 `N` 从 0 到副本数：

```
"Name of Set"-N

```

这意味着名为 `db` 的 Statefulset 有 3 个副本将创建以下 pod：

```
db-0
db-1
db-2

```

这使得 Kubernetes 能够将网络名称和 `PersistentVolumes` 与特定的 pod 关联起来。此外，它还用于对 pod 的创建和终止进行排序。Pod 将从 `0` 开始启动，并从 `N` 开始终止。

# 一个有状态的示例

让我们看一个有状态应用程序的示例。首先，我们将想要创建和使用一个 `StorageClass`，正如我们之前讨论的一样。这将允许我们连接到 Google Cloud Persistent Disk provisioner。Kubernetes 社区正在为各种 `StorageClasses` 构建 provisioners，包括 GCP 和 AWS。每个 provisioner 都有一组可用的参数。GCP 和 AWS 提供商都可以让您选择磁盘类型（固态、标准等）以及故障域，这是需要与其附加的 pod 匹配的。AWS 还允许您指定加密参数以及针对 Provisioned IOPs 卷的 IOPs。还有一些其他 provisioner 正在进行中，包括 Azure 和各种非云选项：

```
kind: StorageClass
apiVersion: storage.k8s.io/v1beta1
metadata:
  name: solidstate
provisioner: kubernetes.io/gce-pd
parameters:
  type: pd-ssd
  zone: us-central1-b

```

*图示 6-7：* `solidstate-sc.yaml`

使用以下命令与前面的列表一起创建 `StorageClass` 类型的 SSD 驱动器在 `us-central1-b` 中：

```
$ kubectl create -f solidstate.yaml

```

接下来，我们将使用我们信任的 `httpwhalesay` 演示创建一个 `StatefulSet` 类型（您可以在本章末尾的 *参考资料* 中参考更多详细信息）。虽然该应用程序确实包含任何真实状态，但我们可以看到存储索赔并探索通信路径：

```
apiVersion: apps/v1beta1
kind: StatefulSet
metadata:
  name: whaleset
spec:
  serviceName: sayhey-svc
  replicas: 3
  template:
    metadata:
      labels:
        app: sayhey
    spec:
      terminationGracePeriodSeconds: 10
      containers:
      - name: sayhey
        image: jonbaier/httpwhalesay:0.2
        command: ["node", "index.js", "Whale it up!."]
        ports:
        - containerPort: 80
          name: web
        volumeMounts:
        - name: www
          mountPath: /usr/share/nginx/html
  volumeClaimTemplates:
  - metadata:
      name: www
      annotations:
        volume.beta.kubernetes.io/storage-class: solidstate
    spec:
      accessModes: [ "ReadWriteOnce" ]
      resources:
        requests:
          storage: 1Gi

```

*图示 6-8：* `sayhey-statefulset.yaml`

使用以下命令开始创建此 StatefulSet。如果您仔细观察 pod 的创建，您将看到它连续创建 whaleset-0、whaleset-1 和 whaleset-2：

```
$ kubectl create -f sayhey-statefulset.yaml

```

紧接着，我们可以使用熟悉的 `get` 子命令看到我们的 StatefulSet 和相应的 pod：

```
$ kubectl get statefulsets
$ kubectl get pods

```

这些 pod 应该会创建类似于以下图像的输出：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_06_05.png)

StatefulSet 列表

`get pods` 输出将显示以下内容：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_06_06.png)

由 StatefulSet 创建的 pod

根据您的时间安排，可能仍在创建 pod。如前面的图像所示，第三个容器仍在启动。

我们还可以看到集合为每个 pod 创建的卷和索赔。首先是 PersistentVolumes 本身：

```
$ kubectl get pv 

```

上述命令应显示三个名为`www-whaleset-N`的 PersistentVolumes。我们注意到大小为`1Gi`，访问模式设置为**ReadWriteOnce**（`RWO`），就像我们在 StorageClass 中定义的一样：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_06_07.png)

持久卷清单

接下来，我们可以查看为每个 pod 保留卷的 PersistentVolumeClaims：

```
$ kubectl get pvc

```

以下是前述命令的输出：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_06_08.png)

持久卷索赔清单

在这里，您会注意到与 PV 自身相同的设置很多。您可能还会注意到声明名称的结尾（或上一个列表中的 PV 名称）看起来像`www-whaleset-N`。`www`是我们在之前的 YAML 定义中指定的挂载名称。然后将其附加到 pod 名称以创建实际的 PV 和 PVC 名称。我们还可以确保与之关联的适当磁盘与匹配的 pod 相关联。

另一个这种对齐很重要的领域是网络通信。StatefulSets 在这里也提供一致的命名。在我们这样做之前，让我们创建一个服务端点，这样我们就有了一个常见的入口点用于传入的请求：

```
apiVersion: v1
kind: Service
metadata:
  name: sayhey-svc
  labels:
    app: sayhey
spec:
  ports:
  - port: 80
    name: web
  clusterIP: None
  selector:
    app: sayhey

```

*清单 6-9：*`sayhey-svc.yaml`

```
$ kubectl create -f sayhey-svc.yaml

```

现在让我们在其中一个 pod 中打开一个 shell，并查看是否可以与集合中的另一个 pod 通信：

```
$ kubectl exec whaleset-0 -i -t bash

```

执行上述命令会在第一个鲸鱼集群（whaleset）的 pod 中给我们提供一个 bash shell。现在我们可以使用`Service`名称来发出一个简单的 HTTP 请求。我们可以同时使用简称`sayhey-svc`和完全限定名称`sayhey-svc.default.svc.cluster.local`：

```
$ curl sayhey-svc
$ curl sayhey-svc.default.svc.cluster.local

```

您将看到与以下图像类似的输出。服务端点充当所有三个 pod 的共同通信点：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_06_09-1.png)

HTTP Whalesay curl 输出（whalesay-0 Pod）

现在让我们看看是否可以与 StatefulSet 中的特定 pod 进行通信。正如我们之前注意到的，StatefulSet 以有序的方式命名 pod。它还以类似的方式为它们提供主机名，以便为集合中的每个 pod 创建一个特定的 DNS 条目。同样，我们将看到`"集合名称"-N`的约定，然后添加完全限定的服务 URL。下面的示例展示了这一点，对于我们集合中的第二个 pod`whaleset-1`：

```
$ curl whaleset-1.sayhey-svc.default.svc.cluster.local

```

在鲸鱼集群（whaleset）的 Bash shell 中运行此命令将显示来自`whaleset-1`的输出：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_06_10-1.png)

HTTP Whalesay curl 输出（whalesay-1 Pod）

您现在可以使用`exit`退出此 shell。

出于学习目的，更详细地描述此部分的某些项目也很有益。例如，`kubectl describe svc sayhey-svc`将显示服务端点中的所有三个 pod IP 地址。

# 概要

在本章中，我们探讨了各种持久存储选项以及如何在我们的 pod 中实现它们。我们查看了 PersistentVolumes 以及允许我们将存储分配和应用程序存储请求分开的 PersistentVolumeClaims。此外，我们还查看了 StorageClasses，以根据规范为存储组提供存储。

我们还探讨了新的 StatefulSets 抽象，并学习了如何以一致和有序的方式部署有状态的应用程序。在下一章中，我们将看看如何将 Kubernetes 与持续集成和交付流水线集成起来。

# 参考资料

1.  [`cloud.google.com/persistent-disk/`](https://cloud.google.com/persistent-disk/)

1.  HTTP Whalesay 是 Docker whalesaym 的一种适应，而 Docker whalesaym 又是 Linux cowsay（大约在 1999 年，Tony Monroe）的一种适应 - [`hub.docker.com/r/docker/whalesay/`](https://hub.docker.com/r/docker/whalesay/)


# 第七章：持续交付

本章将向读者展示如何将他们的构建流程和部署与 Kubernetes 集群集成。它将涵盖如何使用 Gulp.js 和 Jenkins 与您的 Kubernetes 集群配合使用的概念。

本章将讨论以下主题：

+   与持续部署流水线集成

+   使用 Gulp.js 与 Kubernetes

+   将 Jenkins 与 Kubernetes 集成

# 与持续交付流水线集成

持续集成和交付是现代开发工作室的关键组成部分。对于任何正在开发自己软件的公司来说，*上线速度*或*收益的平均时间*至关重要。我们将看看 Kubernetes 如何帮助您。

**CI/CD**（持续集成/持续交付的缩写）通常需要在代码库推送更改时提供临时构建和测试服务器。Docker 和 Kubernetes 非常适合这项任务，因为可以轻松在几秒钟内创建容器，并在运行构建后同样轻松地将其删除。此外，如果您的集群上已经有大量基础设施可用，那么利用空闲容量进行构建和测试是有意义的。

在本文中，我们将探讨用于构建和部署软件的两种流行工具：

+   **Gulp.js**：这是一个简单的任务执行器，用于使用**JavaScript**和**Node.js**自动化构建过程。

+   **Jenkins**：这是一个完整的持续集成服务器

# Gulp.js

Gulp.js 为我们提供了*Build as code*的框架。类似于*基础设施即代码*，这使我们能够以程序方式定义我们的构建过程。我们将通过一个简短的示例演示如何从 Docker 镜像构建到最终 Kubernetes 服务创建一个完整的工作流程。

# 先决条件

对于本文的这一部分，您需要已安装并准备好一个**NodeJS**环境，包括**node 包管理器**（**npm**）。如果您尚未安装这些软件包，可以在[`docs.npmjs.com/getting-started/installing-node`](https://docs.npmjs.com/getting-started/installing-node)找到安装说明。

您可以通过执行`node -v`命令检查 NodeJS 是否已正确安装。

您还需要**Docker CE**和一个**DockerHub**帐户来推送一个新的镜像。您可以在[`docs.docker.com/installation/`](https://docs.docker.com/installation/)找到安装 Docker CE 的说明。

您可以在[`hub.docker.com/`](https://hub.docker.com/)轻松创建一个 DockerHub 帐户。

在您拥有凭证后，您可以使用`$ docker login`命令通过 CLI 登录。

# Gulp 构建示例

让我们从创建一个名为`node-gulp`的项目目录开始：

```
$ mkdir node-gulp
$ cd node-gulp

```

接下来，我们将安装`gulp`包，并通过运行带有版本标志的`npm`命令来检查它是否准备好，如下所示：

```
$ npm install -g gulp

```

您可能需要打开一个新的终端窗口，确保`gulp`在您的路径上。同时，确保返回到您的`node-gulp`目录：

```
 $ gulp -v

```

接下来，我们将在项目文件夹中本地安装`gulp`以及`gulp-git`和`gulp-shell`插件，如下所示：

```
$ npm install --save-dev gulp
$ npm install gulp-git -save
$ npm install --save-dev gulp-shell

```

最后，我们需要创建一个 Kubernetes 控制器和服务定义文件，以及一个`gulpfile.js`文件，来运行我们的所有任务。同样，如果你希望复制它们，这些文件也可以在书籍文件包中找到。参考以下代码：

```
apiVersion: v1 
kind: ReplicationController 
metadata: 
  name: node-gulp 
  labels: 
    name: node-gulp 
spec: 
  replicas: 1 
  selector: 
    name: node-gulp 
  template: 
    metadata: 
      labels: 
        name: node-gulp 
    spec: 
      containers: 
      - name: node-gulp 
        image: <your username>/node-gulp:latest 
        imagePullPolicy: Always 
        ports: 
        - containerPort: 80 

```

*清单 7-1*：`node-gulp-controller.yaml`

正如你所见，我们有一个基本的控制器。你需要用你的 Docker Hub 用户名替换`**<your username>**/node-gulp:latest`：

```
apiVersion: v1 
kind: Service 
metadata: 
  name: node-gulp 
  labels: 
    name: node-gulp 
spec: 
  type: LoadBalancer 
  ports: 
  - name: http 
    protocol: TCP 
    port: 80 
  selector: 
    name: node-gulp 

```

*清单 7-2*：`node-gulp-service.yaml`

接下来，我们有一个简单的服务，它选择我们控制器中的 pods，并创建一个外部负载平衡器以便访问，就像以前一样：

```
var gulp = require('gulp'); 
var git = require('gulp-git'); 
var shell = require('gulp-shell'); 

// Clone a remote repo 
gulp.task('clone', function(){ 
  return git.clone('https://github.com/jonbaierCTP/getting-started-with-kubernetes-se.git', function (err) { 
    if (err) throw err; 
  }); 

}); 

// Update codebase 
gulp.task('pull', function(){ 
  return git.pull('origin', 'master', {cwd: './getting-started-with-kubernetes-se'}, function (err) { 
    if (err) throw err; 
  }); 
}); 

//Build Docker Image 
gulp.task('docker-build', shell.task([ 
  'docker build -t <your username>/node-gulp ./getting-started-with-kubernetes-se/docker-image-source/container-info/', 
  'docker push <your username>/node-gulp' 
])); 

//Run New Pod 
gulp.task('create-kube-pod', shell.task([ 
  'kubectl create -f node-gulp-controller.yaml', 
  'kubectl create -f node-gulp-service.yaml' 
])); 

//Update Pod 
gulp.task('update-kube-pod', shell.task([ 
  'kubectl delete -f node-gulp-controller.yaml', 
  'kubectl create -f node-gulp-controller.yaml' 
])); 

```

*清单 7-3*：`gulpfile.js`

最后，我们有`gulpfile.js`文件。这是我们定义所有构建任务的地方。同样，在`**<your username>**/node-gulp`部分填入你的 Docker Hub 用户名。

浏览文件，首先，克隆任务从 GitHub 下载我们的镜像源代码。拉取任务在克隆的存储库上执行`git pull`。接下来，`docker-build`命令从`container-info`子文件夹构建镜像并将其推送到 DockerHub。最后，我们有`create-kube-pod`和`update-kube-pod`命令。你可以猜到，`create-kube-pod`命令首次创建我们的控制器和服务，而`update-kube-pod`命令只是替换控制器。

让我们继续运行这些命令，看看我们的端到端工作流程：

```
$ gulp clone
$ gulp docker-build

```

第一次运行时，你可以执行以下`create-kube-pod`命令：

```
$ gulp create-kube-pod

```

就是这样。如果我们对`node-gulp`服务运行快速的`kubectl describe`命令，我们可以获取到新服务的外部 IP。浏览该 IP，你会看到熟悉的`container-info`应用程序正在运行。请注意，主机以`node-gulp`开头，就像我们在前面提到的 pod 定义中命名的一样：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_07_01.png)

由 Gulp 构建启动的服务

在后续更新中，像这样运行`pull`和`update-kube-pod`命令：

```
$ gulp pull
$ gulp docker-build
$ gulp update-kube-pod

```

这只是一个非常简单的示例，但你可以开始看到如何通过几行简单的代码协调你的构建和部署端到端是多么容易。接下来，我们将看看如何使用 Kubernetes 来实际运行 Jenkins 构建。

# 用于 Jenkins 的 Kubernetes 插件

我们可以使用 Kubernetes 运行我们的 CI/CD 流水线的一种方式是在容器化环境中运行我们的 Jenkins 构建节点。幸运的是，已经有一个插件，由 Carlos Sanchez 编写，允许你在 Kubernetes 的 pods 中运行 Jenkins 构建节点。

# 先决条件

你将需要一个 Jenkins 服务器来执行下一个示例。如果你没有可用的，你可以使用 Docker Hub 上提供的一个 Docker 镜像 [`hub.docker.com/_/jenkins/`](https://hub.docker.com/_/jenkins/)。

通过 Docker CLI 运行它就是这么简单的：

```
docker run --name myjenkins -p 8080:8080 -v /var/jenkins_home jenkins 

```

# 安装插件

登录到您的 Jenkins 服务器，从主页仪表板中，点击“管理 Jenkins”。然后，从列表中选择“管理插件”。

对于安装新的 Jenkins 服务器的注意事项：当您首次登录到 Jenkins 服务器时，它会要求您安装插件。选择默认插件或不安装插件将不会安装任何插件：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_07_02.png)

Jenkins 主面板

凭证插件是必需的，但应默认安装。如果有疑问，可以在“已安装”选项卡中查看，如下所示的截图：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_07_03.png)

Jenkins 已安装的插件

接下来，我们可以点击“可用”选项卡。Kubernetes 插件应该位于“集群管理和分布式构建”或“Misc (cloud)”下。有许多插件，因此您也可以在页面上搜索 Kubernetes。勾选 Kubernetes 插件的框，并点击“安装而不重启”。

这将安装 Kubernetes 插件和 Durable Task 插件：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_07_04.png)

插件安装

如果您希望安装非标准版本或只是喜欢调整，您可以选择下载插件。最新的 **Kubernetes** 和 **Durable Task** 插件可以在这里找到：

Kubernetes 插件: [`wiki.jenkins-ci.org/display/JENKINS/Kubernetes+Plugin`](https://wiki.jenkins-ci.org/display/JENKINS/Kubernetes+Plugin)         Durable Task 插件: [`wiki.jenkins-ci.org/display/JENKINS/Durable+Task+Plugin`](https://wiki.jenkins-ci.org/display/JENKINS/Durable+Task+Plugin) 接下来，我们可以点击“高级”选项卡，然后滚动到“上传插件”。导航到`durable-task.hpi`文件，然后点击“上传”。您应该会看到一个显示安装进度条的屏幕。一两分钟后，它将更新为“成功”。

最后，安装主要的 Kubernetes 插件。在左侧，点击“管理插件”，然后再次点击“高级”选项卡。这次，上传`kubernetes.hpi`文件，然后点击“上传”。几分钟后，安装应该完成。

# 配置 Kubernetes 插件

点击“返回仪表板”或左上角的 Jenkins 链接。从主仪表板页面，点击“凭据”链接。从列表中选择一个域；在我的情况下，我只是使用了默认的全局凭据域。点击“添加凭据”：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_07_05.png)

添加凭据屏幕

将“类型”留为空，将“范围”设置为全局。添加您的 Kubernetes 管理员凭据。请记住，您可以通过运行`config`命令找到这些凭据：

```
$ kubectl config view

```

您可以将 ID 留空，给它一个明智的描述，然后点击“确定”按钮。

现在我们已经保存了凭证，我们可以添加我们的 Kubernetes 服务器。点击左上角的 Jenkins 链接，然后选择“管理 Jenkins”。从那里，选择“配置系统”，然后滚动到最底部的“云”部分。从“添加新云”下拉菜单中选择 Kubernetes，将出现一个 Kubernetes 部分，如下所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_07_06_EDIT.png)

新 Kubernetes 云设置

您需要以 `https://<Master IP>/` 的形式指定主节点的 URL。

接下来，从下拉列表中选择我们添加的凭据。由于 Kubernetes 默认使用自签名证书，您还需要检查“禁用 HTTPS 证书检查”复选框。

点击“测试连接”，如果一切顺利，您应该看到“连接成功”按钮旁边出现。

如果您使用的是插件的旧版本，可能看不到“禁用 HTTPS 证书检查”复选框。如果是这种情况，您需要直接在 **Jenkins 主节点** 上安装自签名证书。

最后，通过在图像旁边的“添加 Pod 模板”下拉菜单中选择 Kubernetes Pod 模板，我们将添加一个 Pod 模板。

这将创建另一个新的部分。在名称和标签部分使用 `jenkins-slave`。点击“容器”旁边的“添加”，再次使用 `jenkins-slave` 作为名称。使用 `csanchez/jenkins-slave` 作为 Docker 镜像，工作目录保留为 `/home/jenkins`。

标签可在构建设置中稍后使用，强制构建使用 Kubernetes 集群：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_07_07.png)

Kubernetes 集群添加

这是扩展到集群添加下面的 Pod 模板：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_07_08.png)

Kubernetes Pod 模板

点击保存，设置完成。现在，Jenkins 中创建的新构建可以使用我们刚刚创建的 Kubernetes Pod 中的从节点。

这里有关防火墙的另一个注意事项。Jenkins 主节点需要能够被 Kubernetes 集群中的所有机器访问，因为 Pod 可能会部署到任何地方。您可以在 Jenkins 的“管理 Jenkins”和“配置全局安全性”下找到端口设置。

# 额外的乐趣

**Fabric8** 自称为一个集成平台。它包括各种日志记录、监视和持续交付工具。它还有一个漂亮的控制台、一个 API 注册表，以及一个 3D 游戏，让您可以射击您的 Pod。这是一个非常酷的项目，实际上是在 Kubernetes 上运行的。请参考 [`fabric8.io/`](http://fabric8.io/)。

在您的 Kubernetes 集群上设置起来非常简单，所以请参考 [`fabric8.io/guide/getStarted/gke.html`](http://fabric8.io/guide/getStarted/gke.html)。

# 总结

我们看了两个可与 Kubernetes 一起使用的持续集成工具。我们简要介绍了如何在我们的集群上部署 Gulp.js 任务。我们还看了一个新插件，用于将 Jenkins 构建从节点集成到您的 Kubernetes 集群中。现在，您应该更好地了解 Kubernetes 如何与您自己的 CI/CD 管道集成。


# 第八章：监控和日志记录

本章将涵盖对我们的 Kubernetes 集群中内置和第三方监控工具的使用和自定义。我们将介绍如何使用这些工具来监视我们集群的健康和性能。此外，我们还将研究内置日志记录、**Google Cloud Logging** 服务和 **Sysdig**。

本章将讨论以下主题：

+   Kubernetes 如何使用 cAdvisor、Heapster、InfluxDB 和 Grafana

+   自定义默认 Grafana 仪表盘

+   使用 FluentD 和 Grafana

+   安装和使用日志记录工具

+   使用流行的第三方工具，如 StackDriver 和 Sysdig，来扩展我们的监控能力

# 监控操作

实际监控远不止检查系统是否正常运行。尽管像你在第二章中学到的那样，*Pods、Services、Replication Controllers 和 Labels* 中的 *健康检查* 部分所学的可以帮助我们隔离问题应用程序。但是，只有在系统下线之前能够预见问题并加以缓解时，运营团队才能最好地为业务服务。

监控的最佳实践是测量核心资源的性能和使用情况，并观察是否存在偏离正常基线的趋势。容器在这方面也不例外，管理我们的 Kubernetes 集群的一个关键组件是清晰地了解所有节点上的操作系统、网络、系统（CPU 和内存）和存储资源的性能和可用性。

在本章中，我们将研究几种选项，以监控和测量所有集群资源的性能和可用性。此外，当出现异常趋势时，我们还将查看一些警报和通知选项。

# 内置监控

如果你回忆一下第一章中关于 Kubernetes 的介绍，我们注意到我们的节点已经运行了许多监控服务。我们可以通过以下方式再次运行 `get pods` 命令，并指定 `kube-system` 命名空间来查看这些服务：

```
$ kubectl get pods --namespace=kube-system

```

以下截图是上述命令的结果：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_08_01.png)

系统 Pod 列表

再次看到了各种各样的服务，但这一切又是如何结合在一起的呢？如果你回忆一下第二章中关于 *节点（原名为 minions）* 部分，每个节点都在运行一个 kublet。Kublet 是节点与 API 服务器交互和更新的主要接口。其中一个更新是节点资源的 **度量值**。实际上，资源使用情况的报告由一个名为 **cAdvisor** 的程序执行。

cAdvisor 是 Google 的另一个开源项目，提供了有关容器资源使用情况的各种指标。指标包括 CPU、内存和网络统计信息。不需要告诉 cAdvisor 关于单个容器的信息；它会收集节点上所有容器的指标，并将其报告给 kublet，然后再报告给 Heapster。

**Google 的开源项目** Google 有许多与 Kubernetes 相关的开源项目。查看它们，使用它们，甚至贡献您自己的代码！

cAdvisor 和 Heapster 在下一节中提到：

+   **cAdvisor**: [`github.com/google/cadvisor`](https://github.com/google/cadvisor)

+   **Heapster**: [`github.com/kubernetes/heapster`](https://github.com/kubernetes/heapster)

**Contrib** 是各种不属于核心 Kubernetes 的组件的集合。其位置在：

[`github.com/kubernetes/contrib`](https://github.com/kubernetes/contrib).

**LevelDB** 是 InfluxDB 创建时使用的键存储库。其位置在：

[`github.com/google/leveldb`](https://github.com/google/leveldb).

**Heapster** 是 Google 的又一个开源项目；你可能开始看到这里出现了一个主题（参见前面的信息框）。Heapster 在一个 minion 节点上的容器中运行，并从 kublet 聚合数据。提供了一个简单的 REST 接口来查询数据。

使用 GCE 设置时，为我们设置了一些额外的包，这为我们节省了时间，并提供了一个完整的包来监视我们的容器工作负载。从前面的 *系统 pod 列表* 截图中可以看到，还有另一个带有 `influx-grafana` 的 pod。

**InfluxDB** 在其官方网站上描述如下（您可以在本章末尾的 *参考* 部分的第 1 点中找到更多详细信息）：

一个没有外部依赖的开源分布式时间序列数据库。

InfluxDB 基于一个键存储包（参考前面的 *Google 的开源项目* 信息框）构建，并且非常适合存储和查询事件或者时间统计信息，例如由 Heapster 提供的那些。

最后，我们有 **Grafana**，它为存储在 InfluxDB 中的数据提供了仪表板和图形界面。使用 Grafana，用户可以创建自定义监控仪表板，并立即查看其 Kubernetes 集群的健康状况，因此也可以查看其整个容器基础架构的健康状况。

# 探索 Heapster

让我们通过 SSH 快速查看 Heapster pod 所在节点的 REST 接口。首先，我们可以列出 pod 来找到运行 Heapster 的 pod，如下所示：

```
$ kubectl get pods --namespace=kube-system

```

pod 的名称应以 `monitoring-heapster` 开头。运行 `describe` 命令查看它运行在哪个节点上，如下所示：

```
$ kubectl describe pods/<Heapster monitoring Pod> --namespace=kube-system

```

从下面的截图输出中，我们可以看到该 pod 正在 `kubernetes-minion-merd` 上运行。另外，请注意下方几行中的 pod IP，因为我们稍后会用到它：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_08_02.png)

Heapster Pod 详细信息

接下来，我们可以使用熟悉的 `gcloud ssh` 命令 SSH 到这台机器，如下所示：

```
$ gcloud compute --project "<Your project ID>" ssh --zone "<your gce zone>" "<kubernetes minion from describe>"

```

从这里，我们可以直接使用 pod 的 IP 地址访问 Heapster REST API。请记住，Pod IP 不仅在容器中路由，而且还在节点本身上路由。`Heapster` API 在端口 `8082` 上监听，并且我们可以在 `/api/v1/metric-export-schema/` 获取完整的指标列表。

现在让我们通过向我们从 `describe` 命令保存的 Pod IP 地址发出 `curl` 命令来查看列表，如下所示：

```
$ curl -G <Heapster IP from describe>:8082/api/v1/metric-export-schema/

```

我们将看到一个相当长的列表。第一部分显示所有可用的指标。最后两部分列出了我们可以按其过滤和分组的字段。为了您的方便，我添加了以下略微易读一些的表格：

| **指标** | **描述** | **单位** | **类型** |
| --- | --- | --- | --- |
| 正常运行时间 | 容器启动以来的毫秒数 | 毫秒 | 累计 |
| cpu/使用率 | 所有核心上的累计 CPU 使用率 | 纳秒 | 累计 |
| cpu/限制 | 毫核 CPU 限制 | - | 测量值 |
| 内存/使用量 | 总内存使用量 | 字节 | 测量值 |
| 内存/工作集 | 总工作集使用量；工作集是内核正在使用且不容易丢弃的内存 | 字节 | 测量值 |
| 内存/限制 | 内存限制 | 字节 | 测量值 |
| 内存/页面错误 | 页面错误数 | - | 累计 |
| 内存/主要页面错误 | 主要页面错误数 | - | 累计 |
| 网络/接收 | 累计接收到网络的字节数 | 字节 | 累计 |
| 网络/接收错误 | 接收到网络时的累计错误数 | - | 累计 |
| 网络/发送 | 累计发送到网络的字节数 | 字节 | 累计 |
| 网络/发送错误 | 发送到网络时的累计错误数 | - | 累计 |
| 文件系统/使用量 | 文件系统上消耗的总字节数 | 字节 | 测量值 |
| 文件系统/限制 | 文件系统总大小（以字节为单位） | 字节 | 测量值 |
| 文件系统/可用 | 文件系统中剩余的可用字节数 | 字节 | 测量值 |

表 6.1。可用的 Heapster 指标

| **字段** | **描述** | **标签类型** |
| --- | --- | --- |
| `nodename` | 容器运行的节点名称 | 通用 |
| `hostname` | 容器运行的主机名 | 通用 |
| `host_id` | 特定于主机的标识符，由云提供商或用户设置 | 通用 |
| `container_base_image` | 在容器内运行的用户定义的镜像名称 | 通用 |
| `container_name` | 容器的用户提供的名称或系统容器的完整容器名称 | 通用 |
| `pod_name` | Pod 的名称 | Pod |
| `pod_id` | Pod 的唯一 ID | Pod |
| `pod_namespace` | Pod 的命名空间 | Pod |
| `namespace_id` | Pod 命名空间的唯一 ID | Pod |
| `labels` | 用户提供的标签的逗号分隔列表 | Pod |

表 6.2。可用的 Heapster 字段

# 自定义我们的仪表板

现在我们有了字段，我们可以玩得开心了。回想一下我们在第一章中看到的 Grafana 页面，*Kubernetes 入门*。让我们再次打开它，方法是转到我们集群的监控 URL。请注意，您可能需要使用您的集群凭据登录。请参考您需要使用的链接的以下格式：

`https://**<your master IP>**/api/v1/proxy/namespaces/kube-system/services/monitoring-grafana`

我们将看到默认的主页仪表板。点击主页旁边的向下箭头，选择集群。这将显示 Kubernetes 集群仪表板，现在我们可以向面板添加我们自己的统计数据。滚动到底部，点击添加一行。这应该会创建一个新行的空间，并在屏幕左侧显示一个绿色标签。

让我们首先为每个节点（minion）添加一个文件系统使用情况的视图。点击*绿色*标签以展开，然后选择 添加面板，然后选择图表。屏幕上应该会出现一个空图表以及我们自定义图表的查询面板。

此面板中的第一个字段应显示以“SELECT mean("value") FROM ...”开头的查询。点击该字段旁边的 A 字符以展开它。将下一个字段留在 FROM 旁边默认设置，并点击下一个字段以选择测量值。下拉菜单中将显示我们在前面表格中看到的 Heapster 指标。选择 `filesystem/usage_bytes_gauge`。现在，在 SELECT 行中，点击 mean()，然后点击 x 符号将其删除。接下来，点击该行末尾的+ 符号并添加选择器 -> max。然后，您会看到一个 GROUP BY 行，其中包含 time($interval)和 fill(none)。小心地点击 fill 而不是 (none) 部分，然后再次点击 x 符号将其删除。然后，点击该行末尾的+ 符号并选择标签（hostname）。

最后，在屏幕底部，我们应该看到一个按时间间隔分组。在那里输入`5s`，你应该会看到类似以下截图的东西：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_08_03.png)

Heapster pod 详细信息

接下来，让我们点击轴标签，以便设置单位和图例。在左 Y 轴下，点击单位旁边的字段，将其设置为 data -> bytes，标签设置为磁盘空间已用。在右 Y 轴下，将单位设置为 none -> none。接下来，在 图例 标签下，确保选中在选项中显示和在值中最大化。

现在，让我们快速转到通用标签并选择一个标题。在我的情况下，我将其命名为`节点的文件系统磁盘使用情况（最大值）`。

我们不想丢失我们创建的这张漂亮的新图表，所以让我们点击右上角的保存图标。它看起来像一个*软盘*（如果你不知道这是什么，你可以进行谷歌图片搜索）。

在我们点击保存图标后，我们会看到一个绿色的对话框，确认仪表板已保存。现在我们可以点击位于图表详细信息面板上方和图表本身下方的 x 符号。

这将带我们返回仪表板页面。如果我们一直往下滚动，我们会看到我们的新图形。让我们在这一行再添加另一个面板。再次使用*绿色*标签，然后选择 Add Panel -> singlestat。又一次，一个空面板将出现，下面是一个设置表单。

假设我们想要监视特定节点并监视网络使用情况。我们可以首先转到 Metrics 选项卡来轻松完成这项任务。然后展开查询字段，并将 FROM 字段中的第二个值设置为 network/rx。现在，我们可以通过点击行末尾的+符号并从下拉菜单中选择主机名，在 WHERE 子句中指定条件。在 hostname = 后点击 select tag value，并从列表中选择一个 minion 节点。

最后，将**mean()**留给第二个 SELECT 字段：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_08_04.png)

Singlestat 选项

在 Options 选项卡中，确保 Unit format 设置为 data -> bytes，然后在 Spark lines 旁的 Show 框中打勾。**sparkline**可以让我们快速查看价值的最近变化历史。我们可以使用 Background mode 来占据整个背景；默认情况下，它使用值下面的区域。

在 Coloring 中，我们可以选择 Value 或 Background 框并选择 Thresholds and Colors。这将使我们能够根据我们指定的阈值层选择不同颜色的值。请注意，阈值数必须使用未格式化版本。

现在，让我们返回到 General 选项卡，并将标题设置为`Network bytes received (Node35ao)`。使用您的 minion 节点的标识符。再次保存我们的工作并返回仪表板。我们现在应该有一个类似以下截图的行：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_08_05.png)

自定义仪表板面板

Grafana 还有其他许多不同类型的面板供您尝试，例如仪表板列表、插件列表、表格和文本。

正如我们所看到的，构建自定义仪表板并一目了然地监视我们集群的健康状况非常容易。

# FluentD 和 Google Cloud Logging

回顾一下本章一开始的*System pod listing*截图，你可能会注意到一些以`fluentd-cloud-logging-kubernetes...`开头的 pod。在使用 GCE 供应商为您的 K8s 集群提供服务时，这些 pod 会出现。我们集群中的每个节点都有一个这样的 pod，其唯一目的是处理 Kubernetes 日志的处理。

如果我们登录到我们的 Google Cloud Platform 帐户，就可以看到一些在那里处理的日志。只需在左侧，在 Stackdriver 下选择 Logging。这将带我们到一个带有顶部多个下拉菜单的日志列表页面。如果这是您第一次访问该页面，第一个下拉菜单可能会被设定为 Cloud HTTP Load Balancer。

在此下拉菜单中，我们将看到许多 GCE 类型的条目。选择 GCE VM 实例，然后选择 Kubernetes 主节点或其中一个节点。在第二个下拉菜单中，我们可以选择各种日志组，包括 kublet。我们还可以按事件日志级别和日期进行过滤。此外，我们可以使用*播放*按钮实时观看事件流：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_08_06.png)

Google Cloud Logging 过滤器

# FluentD

现在我们知道 `fluentd-cloud-logging-kubernetes` pods 正在将数据发送到 Google Cloud，但是我们为什么需要 FluentD？简而言之，**FluentD** 是一个收集器。它可以配置为具有多个来源来收集和标记日志，然后将其发送到各种输出点进行分析、报警或存档。我们甚至可以在将数据传递给目的地之前使用插件转换数据。

并非所有的提供商设置都默认安装了 FluentD，但这是一种推荐的方法，可以为我们未来的监控运营提供更大的灵活性。AWS Kubernetes 设置也使用 FluentD，但是将事件转发到**Elasticsearch**。

**探索 FluentD** 如果你对 FluentD 设置的内部工作原理感到好奇，或者只是想自定义日志收集，我们可以很容易地使用 `kubectl exec` 命令和本章前面运行的一个 pod 名称进行探索。

首先，让我们看看是否可以找到 FluentD 的 `config` 文件：

`**$ kubectl exec fluentd-cloud-logging-kubernetes-minion-group-r4qt --namespace=kube-system -- ls /etc/td-agent**`

我们将在 `etc` 文件夹中查找，然后在 `td-agent` 文件夹中查找，这是 `fluent` 子文件夹。在这个目录中搜索时，我们应该看到一个 `td-agent.conf` 文件。我们可以使用简单的 `cat` 命令查看该文件，如下所示：

`**$ kubectl exec fluentd-cloud-logging-kubernetes-minion-group-r4qt --namespace=kube-system -- cat /etc/td-agent/td-agent.conf**`

我们应该看到许多来源，包括各种 Kubernetes 组件、Docker 和一些 GCP 元素。

虽然我们可以在这里进行更改，但请记住这是一个正在运行的容器，如果 pod 死亡或重新启动，我们的更改将不会被保存。如果我们真的想自定义，最好使用这个容器作为基础构建一个新的容器，将其推送到存储库以供以后使用。

# 完善我们的监控运营

虽然 Grafana 为我们提供了一个监控容器运营的良好起点，但它仍然是一个正在进行中的工作。在运营的真实世界中，一旦我们知道有问题，拥有完整的仪表板视图就很棒。然而，在日常场景中，我们更愿意采取积极主动的方式，实际上在问题出现时收到通知。这种报警能力对于让运营团队保持领先并避免*被动模式*至关重要。

在这个空间中有许多可用的解决方案，我们将特别关注两个——GCE 监控（StackDriver）和 Sysdig。

# GCE（StackDriver）

**StackDriver** 是公共云基础设施的绝佳起点。实际上，它由 Google 拥有，因此作为 Google 云平台监控服务进行集成。在您的锁定警报开始响起之前，StackDriver 还具有与 AWS 的良好集成。此外，StackDriver 还具有警报功能，支持向各种平台发送通知，并支持用于其他内容的 Webhook。

# 注册 GCE 监控

在 GCE 控制台中，在**Stackdriver**部分点击**监控**。这将打开一个新窗口，我们可以在其中注册 Stackdriver 的免费试用。然后，我们可以添加我们的 GCP 项目，以及可选的 AWS 帐户。这需要一些额外的步骤，但页面上包含了说明。最后，我们将收到有关如何在我们的集群节点上安装代理的说明。我们现在可以跳过这一步，但一会儿会回来。

点击**继续**，设置您的每日警报，然后再次点击**继续**。

点击**启动监控**继续。我们将被带到主仪表板页面，在那里我们将看到集群中节点的一些基本统计信息。如果我们从侧边栏中选择**资源**，然后选择**实例**，我们将被带到列出所有节点的页面。通过点击单个节点，即使没有安装代理，我们也可以再次看到一些基本信息。

Stackdriver 还提供可安装在节点上的监控和日志代理。但是，它当前不支持 GCE `kube-up` 脚本中默认使用的容器 OS。您仍然可以查看 GCE 或 AWS 中任何节点的基本指标，但如果您想要详细的代理安装，则需要使用另一个操作

# 警报

接下来，我们可以查看作为监控服务一部分提供的警报策略。从实例详细信息页面，点击页面顶部的**创建警报策略**按钮。

我们会点击**添加条件**，并选择一个指标阈值。在**目标**部分，将**资源类型**设置为实例（GCE）。然后，将**适用于**设置为组和 kubernetes。将**条件触发如果**设置为任何成员违反。

在**配置**部分，将**如果指标**保持为 CPU 使用率（GCE 监控），将**条件**保持为上述。现在将**阈值**设置为`80`，并将时间设置为 5 分钟。

点击保存条件：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_08_08.png)

Google Cloud 监控警报策略

接下来，我们将添加一个通知。在**通知**部分，将**方法**保持为电子邮件，并输入您的电子邮件地址。

我们可以跳过**文档**部分，但这是我们可以添加文本和格式到警报消息的地方。

最后，将策略命名为`过高的 CPU 负载`，然后点击**保存策略**。

现在，每当我们的实例之一的 CPU 使用率超过 80％，我们将收到电子邮件通知。如果我们需要审查我们的策略，我们可以在**警报**下拉菜单中找到它们，然后在屏幕左侧的菜单中找到**策略概览**。

# 超越系统监控与 Sysdig

监控我们的云系统是一个很好的开始，但是对于容器本身的可见性呢？虽然有各种各样的云监控和可见性工具，但 Sysdig 以其不仅可以深入了解系统操作而且特别是容器而脱颖而出。

Sysdig 是开源的，并被称为*具有对容器的本地支持的通用系统可见性工具*（您可以在本章末尾的*参考资料*部分的第 2 点中了解更多详情）。它是一个命令行工具，可以提供我们之前看过的领域的见解，例如存储、网络和系统进程。它的独特之处在于提供了这些进程和系统活动的详细信息和可见性水平。此外，它对容器有本地支持，这为我们提供了我们容器操作的全貌。这是您容器操作工具库中强烈推荐的工具。Sysdig 的主要网站是 [`www.sysdig.org/`](http://www.sysdig.org/)。

# Sysdig Cloud

我们将马上看一下 Sysdig 工具和一些有用的基于命令行的用户界面。然而，Sysdig 团队还开发了一款商业产品，名为**Sysdig Cloud**，提供了我们在本章前面讨论过的高级仪表板、警报和通知服务。此外，这里的区别在于对容器的高可见性，包括我们应用程序拓扑的一些漂亮的可视化效果。

如果您宁愿跳过*Sysdig Cloud*部分，只想尝试命令行工具，请直接跳到本章后面的*Sysdig 命令行*部分。

如果您还没有注册，请在 [`www.sysdigcloud.com`](http://www.sysdigcloud.com) 上注册 Sysdig Cloud。

第一次激活并登录后，我们将被带到一个欢迎页面。点击“下一步”，我们将看到一个页面，其中有各种选项可以安装`sysdig`代理。对于我们的示例环境，我们将使用 Kubernetes 设置。选择 Kubernetes 将为您提供一个带有 API 密钥和指令链接的页面。该指令将指导您如何在集群上创建 Sysdig 代理 DaemonSet。不要忘记在安装页面上添加 API 密钥。

在代理连接之前，我们将无法继续安装页面。创建 DaemonSet 并等待片刻后，页面应继续到 AWS 集成页面。如果您愿意，您可以填写此表单，但是对于本次演练，我们将点击“跳过”。然后，点击“让我们开始吧”。

就目前而言，Sysdig 和 Sysdig Cloud 与 GCE `kube-up` 脚本默认部署的最新容器操作系统不完全兼容，该操作系统是谷歌的 Container-Optimized OS：[`cloud.google.com/container-optimized-os/docs`](https://cloud.google.com/container-optimized-os/docs)。

我们将被带到主 Sysdig Cloud 仪表板屏幕。在 Explore 选项卡下，我们应该看到至少两个 minion 节点。我们应该看到类似以下带有我们的 minion 节点的截图：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_08_09.png)

Sysdig Cloud 探索页面

此页面显示了一个表格视图，左侧的链接让我们探索一些关键的 CPU、内存、网络等指标。虽然这是一个很好的开始，但详细视图将让我们更深入地了解每个节点。

# 详细视图

让我们来看看这些视图。选择其中一个 minion 节点，然后滚动到下方出现的详细部分。默认情况下，我们应该看到 System: Overview by Process 视图（如果未选中，请从左侧的列表中单击它）。如果图表难以阅读，只需点击每个图表左上角的最大化图标即可获得更大的视图。

有各种有趣的视图可供探索。仅列出其中一些，Services | HTTP Overview 和 Hosts & Containers | Overview by Container 为我们提供了一些很棒的图表供检查。在后一视图中，我们可以看到容器的 CPU、内存、网络和文件使用情况统计。

# 拓扑视图

此外，底部还有三个拓扑视图。这些视图非常适合帮助我们了解我们的应用程序如何通信。点击 Topology | Network Traffic，等待几秒钟让视图完全填充。它应该看起来类似以下截图：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_08_10.png)

Sysdig Cloud 网络拓扑视图

我们注意到视图将集群中的 minion 节点与主节点之间的通信流量进行了映射。您还可以在节点方框的右上角看到一个 + 符号。点击其中一个 minion 节点，然后使用视图区域顶部的缩放工具放大到细节，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_08_11.png)

Sysdig Cloud 网络拓扑详细视图

请注意，现在我们可以看到运行在主节点内的 Kubernetes 的所有组件。我们可以看到各种组件是如何协同工作的。我们将看到 `kube-proxy` 和 `kublet` 进程正在运行，以及一些带有 Docker 鲸鱼标志的方框，这表示它们是容器。如果我们放大并使用加号图标，我们将看到这些是我们的 Pod 和核心 Kubernetes 进程的容器，就像我们在第一章 Chapter 1，*Introduction to* *Kubernetes* 中运行在主节点上的服务部分中所见到的一样。

此外，如果您的监控节点中包括了主节点，我们可以观察 `kublet` 从 minion 发起通信，并一直跟踪到主节点中的 `kube-apiserver` 容器。

我们甚至有时可以看到实例与 GCE 基础架构进行通信以更新元数据。此视图非常适合形成我们的基础架构和底层容器之间如何通信的心理图像。

# 指标

接下来，让我们切换到左侧菜单旁边的 Metrics 标签。在这里，还有各种有用的视图。

让我们来看看 System 中的 `capacity.estimated.request.total.count`。这个视图向我们展示了一个节点在完全加载时可以处理多少请求的估计值。这对基础设施规划非常有用：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_08_12.png)

Sysdig Cloud 容量估算视图

# 警报

现在我们有了所有这些很棒的信息，让我们创建一些通知。滚动到页面顶部，找到一个 minion 条目旁边的铃铛图标。这将打开一个创建警报的对话框。在这里，我们可以设置类似于本章前面所做的手动警报。但是，还有使用 **BASELINE** 和 **HOST COMPARISON** 的选项。

使用 **BASELINE** 选项非常有帮助，因为 Sysdig 将监视节点的历史模式，并在任何一个指标偏离预期指标阈值时向我们发出警报。不需要手动设置，因此这可以真正节省通知设置的时间，并帮助我们的运维团队在问题出现之前采取主动措施。请参考以下图片：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_08_13.png)

Sysdig Cloud 新警报

**HOST COMPARISON** 选项也是一个很好的帮助，因为它允许我们将指标与其他主机进行比较，并在一个主机具有与组不同的指标时发出警报。一个很好的用例是监视 minion 节点之间的资源使用情况，以确保我们的调度约束没有在集群的某个地方创建瓶颈。

您可以选择任何您喜欢的选项并给它一个名称和警告级别。启用通知方法。Sysdig 支持电子邮件，**SNS**（简称**简单通知服务**）和 **PagerDuty** 作为通知方法。您还可以选择启用 **Sysdig Capture** 以更深入地了解问题。一切都设置好后，只需点击创建，您就会开始收到问题警报。

# sysdig 命令行

无论您只使用开源工具还是尝试完整的 Sysdig Cloud 套装，命令行实用程序都是跟踪问题或更深入了解系统的绝佳伴侣。

在核心工具中，有一个主要的 `sysdig` 实用程序，还有一个名为 `csysdig` 的命令行样式的用户界面。让我们看看一些有用的命令。

在这里找到您操作系统的相关安装说明：

[`www.sysdig.org/install/`](http://www.sysdig.org/install/)

安装完成后，让我们首先查看网络活动最多的进程，发出以下命令：

```
$ sudo sysdig -pc -c topprocs_net

```

以下截图是前面命令的结果：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_08_14.png)

按网络活动排名的 Sysdig 高级进程

这是一个交互式视图，将向我们显示网络活动最多的顶级进程。此外，还有大量可与 `sysdig` 一起使用的命令。尝试一下其他几个有用的命令，包括以下内容：

```
$ sudo sysdig -pc -c topprocs_cpu
$ sudo sysdig -pc -c topprocs_file
$ sudo sysdig -pc -c topprocs_cpu container.name=<Container Name NOT ID>

```

更多示例可以在[`www.sysdig.org/wiki/sysdig-examples/`](http://www.sysdig.org/wiki/sysdig-examples/)找到。

# csysdig 命令行 UI

因为我们在一个节点的 shell 上并不意味着我们不能拥有一个 UI。Csysdig 是一个可定制的 UI，用于探索 Sysdig 提供的所有指标和洞察力。只需在提示符下键入`csysdig`：

```
$ csysdig

```

进入 csysdig 后，我们看到机器上所有进程的实时列表。在屏幕底部，您会注意到一个带有各种选项的菜单。点击 Views 或按下*F2*（如果您喜欢使用键盘）。在左侧菜单中，有各种选项，但我们将查看线程。双击以选择线程。

在某些操作系统和某些 SSH 客户端上，您可能会遇到功能键的问题。检查终端的设置，并确保功能键使用 VT100+序列。

我们可以看到当前系统上所有正在运行的线程以及一些关于资源使用情况的信息。默认情况下，我们看到的是一个经常更新的大列表。如果我们点击过滤器，*F4*用于鼠标受挑战者，我们可以简化列表。

在过滤框中键入`kube-apiserver`（如果您在主节点上）或`kube-proxy`（如果您在节点（minion）上），然后按*Enter*。视图现在仅过滤该命令中的线程：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_08_15.png)

Csysdig 线程

如果我们想进一步检查，我们可以简单地选择列表中的一个线程，然后点击 Dig 或按下*F6*。现在我们可以实时查看来自命令的系统调用的详细列表。这可以是一个非常有用的工具，可以深入了解我们集群上正在运行的容器和处理。

点击“返回”或按下*Backspace*键返回上一个屏幕。然后，再次转到“Views”。这次，我们将查看容器视图。再次，我们可以过滤并且还可以使用 Dig 视图来更深入地查看发生在系统调用级别的情况。

在这里你可能注意到的另一个菜单项是 Actions，在最新版本中可用。这些功能使我们能够从进程监视转到操作和响应。它使我们能够从 csysdig 的各种进程视图中执行各种操作。例如，容器视图具有进入 bash shell、杀死容器、检查日志等操作。值得了解各种操作和快捷键，甚至添加您自己的常见操作的自定义快捷键。

# Prometheus

监控领域的一个新手是一个名为**Prometheus**的开源工具。Prometheus 是一个由 SoundCloud 团队构建的开源监控工具。您可以从[`prometheus.io`](https://prometheus.io)了解更多关于该项目的信息。

他们的网站提供以下功能（您可以在本章末尾的*参考资料*中查看更多关于此的详细信息）：

+   一个多维度的[数据模型](https://prometheus.io/docs/concepts/data_model/)（由度量名称和键/值对标识的时间序列）

+   一个[灵活的查询语言](https://prometheus.io/docs/querying/basics/)来利用这种多维性

+   不依赖于分布式存储；单服务器节点是自主的

+   时间序列收集通过 HTTP 的拉模型实现

+   通过一个中间网关支持[推送时间序列](https://prometheus.io/docs/instrumenting/pushing/)

+   目标通过服务发现或静态配置发现

+   多种图形和仪表板支持模式

CoreOS 在这里有一篇关于如何在 Kubernetes 中设置 Prometheus 的好博文：

[`coreos.com/blog/monitoring-kubernetes-with-prometheus.html`](https://coreos.com/blog/monitoring-kubernetes-with-prometheus.html)

# 总结

我们简要了解了如何使用 Kubernetes 监控和记录。现在您应该对 Kubernetes 如何使用 cAdvisor 和 Heapster 收集给定集群中所有资源的指标有所了解。此外，我们还看到 Kubernetes 通过提供 InfluxDB 和 Grafana 设置和配置可以为我们节省时间。仪表板可以根据我们的日常运营需求进行轻松定制。

此外，我们还查看了使用 FluentD 和 Google 云日志服务的内置日志功能。此外，Kubernetes 通过为我们设置基础提供了极大的节约时间。

最后，您了解了监控我们的容器和集群的各种第三方选项。使用这些工具将使我们能够更深入地了解我们应用程序的健康和状态。所有这些工具结合在一起，为我们提供了一个扎实的工具集来管理我们的日常运营。

在下一章中，我们将探讨新的集群联邦功能。尽管仍然主要处于测试阶段，但这个功能将允许我们在不同数据中心甚至云中运行多个集群，但通过单一控制平面管理和分发应用程序。

# 参考文献

1.  [`stackdriver.com/`](http://stackdriver.com/)

1.  [`www.sysdig.org/wiki/`](http://www.sysdig.org/wiki/)

1.  [`prometheus.io/docs/introduction/overview/`](https://prometheus.io/docs/introduction/overview/)
