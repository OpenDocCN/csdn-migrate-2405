# Kubernetes 研讨会（七）

> 原文：[`zh.annas-archive.org/md5/DFC15E6DFB274E63E53841C0858DE863`](https://zh.annas-archive.org/md5/DFC15E6DFB274E63E53841C0858DE863)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十五章： Kubernetes 中的监控和自动扩展

概述

本章将介绍 Kubernetes 如何使您能够监视集群和工作负载，然后使用收集的数据自动驱动某些决策。您将了解 Kubernetes Metric Server，它汇总了所有集群运行时信息，使您能够使用这些信息来驱动应用程序运行时的扩展决策。我们将指导您如何使用 Kubernetes Metrics 服务器和 Prometheus 设置监控，然后使用 Grafana 来可视化这些指标。到本章结束时，您还将学会如何自动扩展您的应用程序以充分利用所提供的基础设施的资源，以及根据需要自动扩展您的集群基础设施。

# 介绍

让我们花一点时间回顾一下我们在这一系列章节中的进展，从第十一章“构建您自己的 HA 集群”开始。我们首先使用 kops 设置了一个 Kubernetes 集群，以高可用的方式配置 AWS 基础设施。然后，我们使用 Terraform 和一些脚本来提高集群的稳定性，并部署我们的简单计数器应用程序。之后，我们开始加固安全性，并使用 Kubernetes/云原生原则增加我们应用程序的可用性。最后，我们学会了运行一个负责使用事务来确保我们始终从我们的应用程序中获得一系列递增数字的有状态数据库。

在本章中，我们将探讨如何利用 Kubernetes 已有的关于我们应用程序的数据，驱动和自动化关于调整其规模的决策过程，以便始终使其适合我们的负载。由于观察应用程序指标、调度和启动容器以及从头开始引导节点需要时间，因此这种扩展并非瞬间发生，但最终（通常在几分钟内）会平衡集群上执行负载工作所需的 Pod 和节点数量。为了实现这一点，我们需要一种获取这些数据、理解/解释这些数据并利用这些数据向 Kubernetes 反馈指令的方法。幸运的是，Kubernetes 中已经有一些工具可以帮助我们做到这一点。这些工具包括 Kubernetes Metric Server、HorizontalPodAutoscalers（HPAs）和 ClusterAutoscaler。

# Kubernetes 监控

Kubernetes 内置支持提供有关基础设施组件以及各种 Kubernetes 对象的有用监控信息。 Kubernetes Metrics 服务器是一个组件（不是内置的），它会在 API 服务器的 API 端点上收集和公开指标数据。 Kubernetes 使用这些数据来管理 Pod 的扩展，但这些数据也可以被第三方工具（如 Prometheus）抓取，供集群操作员使用。 Prometheus 具有一些非常基本的数据可视化功能，并且主要用作度量收集和存储工具，因此您可以使用更强大和有用的数据可视化工具，如 Grafana。 Grafana 允许集群管理员创建有用的仪表板来监视其集群。 您可以在此链接了解有关 Kubernetes 监控架构的更多信息：[`github.com/kubernetes/community/blob/master/contributors/design-proposals/instrumentation/monitoring_architecture.md`](https://github.com/kubernetes/community/blob/master/contributors/design-proposals/instrumentation/monitoring_architecture.md)。

以下是我们在图表中的展示：

![图 15.1：监控管道概述我们将在本章实施的](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_15_01.jpg)

图 15.1：我们将在本章实施的监控管道概述

该图表代表了通过各种 Kubernetes 对象实施监控管道的方式。 总之，监控管道将按以下方式工作：

1.  Kubernetes 的各个组件已经被调整，以提供各种指标。 Kubernetes Metrics 服务器将从这些组件中获取这些指标。

1.  Kubernetes Metrics 服务器将在 API 端点上公开这些指标。

1.  Prometheus 将访问此 API 端点，抓取这些指标，并将其添加到其特殊数据库中。

1.  Grafana 将查询 Prometheus 数据库，收集这些指标，并在整洁的仪表板上以图表和其他可视化形式呈现。

现在，让我们逐个查看之前提到的每个组件，以更好地理解它们。

## Kubernetes Metrics API/Metrics 服务器

Kubernetes Metrics server（以前称为 Heapster）收集并公开所有 Kubernetes 组件和对象的运行状态的度量数据。节点、控制平面组件、运行中的 pod 以及任何 Kubernetes 对象都可以通过 Metrics server 进行观察。它收集的一些度量的例子包括 Deployment/ReplicaSet 中所需 pod 的数量，该部署中处于`Ready`状态的 pod 的数量，以及每个容器的 CPU 和内存利用率。

在收集与我们编排应用程序相关的信息时，我们将主要使用默认公开的度量。

## Prometheus

Prometheus 是一个度量收集器、时间序列数据库和警报管理器，几乎可以用于任何事情。它利用抓取功能从运行中的进程中提取度量，这些度量以 Prometheus 格式在定义的间隔内暴露。然后这些度量将存储在它们自己的时间序列数据库中，您可以对这些数据运行查询，以获取运行应用程序状态的快照。

它还带有警报管理器功能，允许您设置触发器以警报您的值班管理员。例如，您可以配置警报管理器，如果您的一个节点的 CPU 利用率在 15 分钟内超过 90%，则自动触发警报。警报管理器可以与多个第三方服务进行接口，通过各种方式发送警报，如电子邮件、聊天消息或短信电话警报。

注意：

如果您想了解更多关于 Prometheus 的信息，可以参考这本书：[`www.packtpub.com/virtualization-and-cloud/hands-infrastructure-monitoring-prometheus`](https://www.packtpub.com/virtualization-and-cloud/hands-infrastructure-monitoring-prometheus)。

## Grafana

Grafana 是一个开源工具，可用于可视化数据并创建有用的仪表板。Grafana 将查询 Prometheus 数据库以获取度量，并在仪表板图表上绘制它们，这样人类更容易理解并发现趋势或差异。在运行生产集群时，这些工具是必不可少的，因为它们帮助我们快速发现基础设施中的问题并解决问题。

## 监控您的应用程序

虽然应用程序监控超出了本书的范围，但我们将提供一些粗略的指南，以便您可以在这个主题上进行更多的探索。我们建议您以 Prometheus 格式公开应用程序的指标，并使用 Prometheus 对其进行抓取；大多数语言都有许多库可以帮助实现这一点。

另一种方法是使用适用于各种应用程序的 Prometheus 导出器。导出器从应用程序中收集指标并将它们暴露给 API 端点，以便 Prometheus 可以对其进行抓取。您可以在此链接找到一些常见应用程序的开源导出器：[`prometheus.io/docs/instrumenting/exporters/`](https://prometheus.io/docs/instrumenting/exporters/)。

对于您的自定义应用程序和框架，您可以使用 Prometheus 提供的库创建自己的导出器。您可以在此链接找到相关的指南：[`prometheus.io/docs/instrumenting/writing_exporters/`](https://prometheus.io/docs/instrumenting/writing_exporters/)。

一旦您从应用程序中公开并抓取了指标，您可以在 Grafana 仪表板中呈现它们，类似于我们将为监控 Kubernetes 组件创建的仪表板。

## 练习 15.01：设置 Metrics Server 并观察 Kubernetes 对象

在这个练习中，我们将为我们的集群设置 Kubernetes 对象的监控，并运行一些查询和创建可视化来查看发生了什么。我们将安装 Prometheus、Grafana 和 Kubernetes Metrics server：

1.  首先，我们将从*练习 12.02*中的 Terraform 文件重新创建您的 EKS 集群，*使用 Terraform 创建 EKS 集群*。如果您已经有了`main.tf`文件，您可以使用它。否则，您可以运行以下命令来获取它：

```
curl -O https://github.com/PacktWorkshops/Kubernetes-Workshop/blob/master/Chapter12/Exercise12.02/main.tf
```

现在，依次使用以下两个命令来启动和运行您的集群资源：

```
terraform init
terraform apply
```

注意

您将需要`jq`来运行以下命令。`jq`是一个简单的操作 JSON 数据的工具。如果您还没有安装它，您可以使用以下命令来安装：`sudo apt install jq`。

1.  为了在我们的集群中设置 Kubernetes Metrics server，我们需要按顺序运行以下命令：

```
curl -O https://raw.githubusercontent.com/PacktWorkshops/Kubernetes-Workshop/master/Chapter15/Exercise15.01/metrics_server.yaml
kubectl apply -f metrics_server.yaml
```

您应该会看到类似以下的响应：

![图 15.2：部署 Metrics server 所需的所有对象](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_15_02.jpg)

图 15.2：部署 Metrics server 所需的所有对象

1.  为了测试这一点，让我们运行以下命令：

```
kubectl get --raw "/apis/metrics.k8s.io/v1beta1/nodes"
```

注意

如果您收到`ServiceUnavailable`错误，请检查防火墙规则是否允许 API 服务器与运行 Metrics 服务器的节点进行通信。

我们经常使用`kubectl get`命令来命名对象。我们在*第四章*中看到，Kubectl 解释请求，将请求指向适当的端点，并以可读格式格式化结果。但是在这里，由于我们在 API 服务器上创建了自定义端点，我们必须使用`--raw`标志指向它。您应该看到类似以下的响应：

![图 15.3：来自 Kubernetes Metrics 服务器的响应](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_15_03.jpg)

图 15.3：来自 Kubernetes Metrics 服务器的响应

正如我们在这里看到的，响应包含定义度量命名空间、度量值和度量元数据的 JSON 块，例如节点名称和可用区。但是，这些指标并不是非常可读的。我们将利用 Prometheus 对它们进行聚合，然后使用 Grafana 将聚合指标呈现在简洁的仪表板中。

1.  现在，我们正在聚合度量数据。让我们开始使用 Prometheus 和 Grafana 进行抓取和可视化。为此，我们将使用 Helm 安装 Prometheus 和 Grafana。运行以下命令：

```
helm install --generate-name stable/prometheus
```

注意

如果您是第一次安装和运行 helm，您需要运行以下命令来获取稳定的存储库：

`help repo add stable https://kubernetes-charts.storage.googleapis.com/`

您应该看到类似以下的输出：

![图 15.4：安装 Prometheus 的 Helm 图表](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_15_04.jpg)

图 15.4：安装 Prometheus 的 Helm 图表

1.  现在，让我们以类似的方式安装 Grafana：

```
helm install --generate-name stable/grafana
```

您应该看到以下响应：

![图 15.5：安装 Grafana 的 Helm 图表](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_15_05.jpg)

图 15.5：安装 Grafana 的 Helm 图表

在此截图中，请注意`NOTES:`部分，其中列出了两个步骤。按照这些步骤获取 Grafana 管理员密码和访问 Grafana 的端点。

1.  在这里，我们正在运行 Grafana 在上一步输出中显示的第一个命令：

```
kubectl get secret --namespace default grafana-1576397218 -o jsonpath="{.data.admin-password}" | base64 --decode ; echo
```

请使用您获得的命令版本；命令将被定制为您的实例。此命令获取您的密码，该密码存储在一个秘密中，解码它，并在您的终端输出中回显它，以便您可以将其复制以供后续步骤使用。您应该看到类似以下的响应：

```
brM8aEVPCJtRtu0XgHVLWcBwJ76wBixUqkCmwUK)
```

1.  现在，让我们运行 Grafana 要求我们运行的下两个命令，如*图 15.5*中所示：

```
export POD_NAME=$(kubectl get pods --namespace default -l "app.kubernetes.io/name=grafana,app.kubernetes.io/instance=grafana-1576397218" -o jsonpath="{.items[0].metadata.name}")
kubectl --namespace default port-forward $POD_NAME 3000
```

再次使用您的实例获取的命令，因为这将是定制的。这些命令会找到 Grafana 正在运行的 Pod，然后将本地机器的端口映射到它，以便我们可以轻松访问它。您应该会看到以下响应：

```
Forwarding from 127.0.0.1:3000 -> 3000
Forwarding from [::1]:3000 -> 3000
```

注意

在这一步，如果您在获取正确的 Pod 名称时遇到任何问题，您可以简单地运行`kubectl get pods`来找到运行 Grafana 的 Pod 的名称，并使用该名称代替 shell（`$POD_NAME`）变量。因此，您的命令将类似于这样：

`kubectl --namespace default port-forward grafana-1591658222-7cd4d8b7df-b2hlm 3000`。

1.  现在，打开浏览器并访问`http://localhost:3000`以访问 Grafana。您应该会看到以下着陆页面：![图 15.6：Grafana 仪表板的登录页面](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_15_06.jpg)

图 15.6：Grafana 仪表板的登录页面

默认用户名是`admin`，密码是*步骤 6*输出中的值。使用该值登录。

1.  成功登录后，您应该会看到此页面：![图 15.7：Grafana 主页仪表板](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_15_07.jpg)

图 15.7：Grafana 主页仪表板

1.  现在，让我们为 Kubernetes 指标创建一个仪表板。为此，我们需要将 Prometheus 设置为 Grafana 的数据源。在左侧边栏中，点击`配置`，然后点击`数据源`：![图 15.8：从配置菜单中选择数据源](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_15_08.jpg)

图 15.8：从配置菜单中选择数据源

1.  您将看到此页面：![图 15.9：添加数据源选项](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_15_09.jpg)

图 15.9：添加数据源选项

现在，点击`添加数据源`按钮。

1.  您应该会看到带有几个数据库选项的页面。Prometheus 应该在顶部。点击它：![图 15.10：选择 Prometheus 作为 Grafana 仪表板的数据源](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_15_10.jpg)

图 15.10：选择 Prometheus 作为 Grafana 仪表板的数据源

现在，在我们继续到下一个屏幕之前，在这里，我们需要获取 Grafana 将用于从集群内部访问 Prometheus 数据库的 URL。我们将在下一步中执行此操作。

1.  打开一个新的终端窗口并运行以下命令：

```
kubectl get svc --all-namespaces
```

您应该会看到类似以下的响应：

![图 15.11：获取所有服务的列表](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_15_11.jpg)

图 15.11：获取所有服务的列表

复制以`prometheus`开头并以`server`结尾的服务的名称。

1.  在*步骤 12*之后，您将看到以下屏幕截图所示的屏幕：![图 15.12：在 Grafana 中输入我们 Prometheus 服务的地址](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_15_12.jpg)

图 15.12：在 Grafana 中输入我们 Prometheus 服务的地址

在`HTTP`部分的`URL`字段中，输入以下值：

```
http://<YOUR_PROMETHEUS_SERVICE_NAME>.default
```

请注意，您应该看到`数据源正在工作`，如前面的屏幕截图所示。然后，点击底部的`保存并测试`按钮。我们在 URL 中添加`.default`的原因是我们将此 Helm 图表部署到了`default` Kubernetes 命名空间。如果您将其部署到另一个命名空间，您应该用您的命名空间的名称替换`default`。

1.  现在，让我们设置仪表板。回到 Grafana 主页（`http://localhost:3000`），点击左侧边栏上的`+`符号，然后点击`Import`，如下所示：![图 15.13：导航到导入仪表板选项](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_15_13.jpg)

图 15.13：导航到导入仪表板选项

1.  在下一页，您应该看到`Grafana.com 仪表板`字段，如下所示：![图 15.14：输入要从中导入仪表板的源](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_15_14.jpg)

图 15.14：输入要从中导入仪表板的源

将以下链接粘贴到“Grafana.com 仪表板”字段中：

```
https://grafana.com/api/dashboards/6417/revisions/1/download
```

这是一个官方支持的 Kubernetes 仪表板。一旦你在文件外的任何地方点击，你应该自动进入下一个屏幕。

1.  上一步应该引导您到这个屏幕：![图 15.15：将 Prometheus 设置为导入仪表板的数据源](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_15_15.jpg)

图 15.15：将 Prometheus 设置为导入仪表板的数据源

在你看到`prometheus`的地方，点击旁边的下拉列表，选择`Prometheus`，然后点击`Import`。

1.  结果应该如下所示：![图 15.16：用于监视我们集群的 Grafana 仪表板](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_15_16.jpg)

图 15.16：用于监视我们集群的 Grafana 仪表板

正如您所看到的，我们在 Kubernetes 中有一个简洁的仪表板来监视工作负载。在这个练习中，我们部署了我们的 Metric Server 来收集和公开 Kubernetes 对象指标，然后我们部署了 Prometheus 来存储这些指标，并使用 Grafana 来帮助我们可视化 Prometheus 中收集的指标，这将告诉我们在任何时候我们集群中发生了什么。现在，是时候利用这些信息来扩展事物了。

# Kubernetes 中的自动扩展

Kubernetes 允许您自动扩展工作负载以适应应用程序的不断变化的需求。从 Kubernetes 度量服务器收集的信息是用于驱动扩展决策的数据。在本书中，我们将涵盖两种类型的扩展操作——一种影响部署中运行的 pod 数量，另一种影响集群中运行的节点数量。这两种都是水平扩展的例子。让我们简要地直观了解一下 pod 的水平扩展和节点的水平扩展将涉及什么：

+   Pods：假设您在创建 Kubernetes 中的部署时填写了`podTemplate`的`resources:`部分，那么该 pod 中的每个容器都将具有由相应的`cpu`和`memory`字段指定的`requests`和`limits`字段。当处理工作负载所需的资源超出您分配的资源时，通过向部署添加 pod 的额外副本，您可以水平扩展以增加部署的容量。通过让软件进程根据负载为您决定部署中 Pod 的副本数量，您正在*自动扩展*部署，以使副本数量与您定义的用于表示应用程序负载的指标保持一致。应用程序负载的一个指标可能是当前正在使用的分配 CPU 的百分比。

+   节点：每个节点都有一定数量的 CPU（通常以核心数表示）和内存（通常以升表示），可供 Pod 消耗。当所有工作节点的总容量被所有运行的 pod 耗尽时（这意味着所有 Pod 的 CPU 和内存请求/限制都等于或大于整个集群的请求/限制），那么我们已经饱和了集群的资源。为了允许在集群上运行更多的 Pod，或者允许集群中发生更多的自动扩展，我们需要以额外的工作节点的形式增加容量。当我们允许软件进程为我们做出这个决定时，我们被认为是*自动扩展*我们集群的总容量。在 Kubernetes 中，这由 ClusterAutoscaler 处理。

注意

当你增加应用程序的 Pod 副本数量时，这被称为水平扩展，由**HorizontalPodAutoscaler**处理。相反，如果你增加副本的资源限制，那就被称为垂直扩展。Kubernetes 还提供**VerticalPodAutoscaler**，但由于尚未普遍可用且在生产中使用时不安全，我们在此略过。

同时使用 HPA 和 ClusterAutoscalers 可以是公司确保始终有正确数量的应用程序资源部署以满足其负载，并且同时不会支付过多费用的有效方式。让我们在以下小节中分别研究它们。

## HorizontalPodAutoscaler

HPA 负责确保部署中应用程序的副本数量与度量标准测得的当前需求相匹配。这很有用，因为我们可以使用实时度量数据，这些数据已经被 Kubernetes 收集，以始终确保我们的应用程序满足我们在阈值中设定的需求。这对一些不习惯使用数据运行应用程序的应用程序所有者可能是一个新概念，但一旦开始利用可以调整部署大小的工具，你就永远不想回头了。

Kubernetes 在`autoscaling/v1`和`autoscaling/v2beta2`组中有一个 API 资源，用于提供可以针对另一个 Kubernetes 资源运行的自动缩放触发器的定义，这往往是一个 Kubernetes 部署对象。在`autoscaling/v1`的情况下，唯一支持的度量标准是当前的 CPU 消耗，在`autoscaling/v2beta2`的情况下，支持任何自定义度量标准。

HPA 查询 Kubernetes Metric Server 来查看特定部署的度量标准。然后，自动缩放资源将确定当前观察到的度量标准是否超出了缩放目标的阈值。如果是，它将根据负载将部署所需的 Pod 数量增加或减少。

举个例子，考虑一个由电子商务公司托管的购物车微服务。在输入优惠券代码的过程中，购物车服务经历了重负载，因为它必须遍历购物车中的所有商品，并在验证优惠券代码之前搜索其中的活动优惠券。在一个随机的周二早晨，有许多在线购物者使用该服务，并且他们都想使用优惠券。通常情况下，服务会不堪重负，请求会开始失败。然而，如果您能够使用 HPA，Kubernetes 将利用集群的空闲计算能力，以确保有足够的该购物车服务的 Pod 来处理负载。

请注意，简单地对部署进行自动缩放并不是解决应用程序性能问题的“一刀切”解决方案。现代应用程序中有许多可能出现减速的地方，因此应该仔细考虑您的应用程序架构，以查看您可以识别其他瓶颈的地方，而这些瓶颈并不是简单的自动缩放可以解决的。一个这样的例子是数据库上的慢查询性能。然而，在本章中，我们将专注于可以通过 Kubernetes 中的自动缩放来解决的应用程序问题。

让我们来看一下 HPA 的结构，以便更好地理解一些内容：

with_autoscaler.yaml

```
115 apiVersion: autoscaling/v1
116 kind: HorizontalPodAutoscaler
117 metadata:
118   name: shopping-cart-hpa
119 spec:
120   scaleTargetRef:
121     apiVersion: apps/v1
122     kind: Deployment
123     name: shopping-cart-deployment
124   minReplicas: 20
125   maxReplicas: 50
126   targetCPUUtilizationPercentage: 50
```

您可以在此链接找到完整的代码：[`packt.live/3bE9v28`](https://packt.live/3bE9v28)。

在这个规范中，观察以下字段：

+   `scaleTargetRef`：这是被缩放的对象的引用。在这种情况下，它是指向购物车微服务的部署的指针。

+   `minReplicas`：部署中的最小副本数，不考虑缩放触发器。

+   `maxReplicas`：部署中的最大副本数，不考虑缩放触发器。

+   `targetCPUUtilizationPercentage`：部署中所有 Pod 的平均 CPU 利用率的目标百分比。Kubernetes 将不断重新评估此指标，并增加和减少 Pod 的数量，以使实际的平均 CPU 利用率与此目标相匹配。

为了模拟对我们的应用程序的压力，我们将使用**wrk**，因为它很容易配置，并且已经为我们制作了一个 Docker 容器。wrk 是一个 HTTP 负载测试工具。它使用简单，并且只有少量选项；但是，它将能够通过使用多个同时的 HTTP 连接反复发出请求来生成大量负载，针对指定的端点。

注意

您可以在此链接找到有关 wrk 的更多信息：[`github.com/wg/wrk`](https://github.com/wg/wrk)。

在接下来的练习中，我们将使用我们一直在运行的应用程序的修改版本来帮助驱动扩展行为。在我们的应用程序的这个修订版中，我们已经修改了它，使得应用程序以天真的方式执行斐波那契数列计算，直到第 10,000,000 个条目，以便它会稍微更加计算密集，并超过我们的 CPU 自动缩放触发器。如果您检查源代码，您会发现我们已经添加了这个函数：

main.go

```
74 func FibonacciLoop(n int) int { 
75   f := make([]int, n+1, n+2) 
76   if n < 2 { 
77         f = f[0:2] 
78   } 
79   f[0] = 0 
80   f[1] = 1 
81   for i := 2; i <= n; i++ { 
82         f[i] = f[i-1] + f[i-2] 
83   } 
84   return f[n] 
85 } 
```

您可以在此链接找到完整的代码：[`packt.live/3h5wCEd`](https://packt.live/3h5wCEd)。

除此之外，我们将使用 Ingress，我们在*第十二章*中学到的，并且在上一章中构建的相同的 SQL 数据库。

现在，说了这么多，让我们深入研究以下练习中这些自动缩放器的实现。

## 练习 15.02：在 Kubernetes 中扩展工作负载

在这个练习中，我们将整合之前的一些不同部分。由于我们的应用程序目前有几个移动部分，我们需要列出一些步骤，以便您了解我们的方向：

1.  我们需要像*练习 12.02*中一样设置我们的 EKS 集群，使用 Terraform 创建一个集群。

1.  我们需要为 Kubernetes Metrics 服务器设置所需的组件。

注意

考虑到这两点，您需要成功完成上一个练习才能执行这个练习。

1.  我们需要使用修改后的计数器应用程序进行安装，以便它成为一个计算密集型的练习，以获取序列中的下一个数字。

1.  我们需要安装 HPA 并设置 CPU 百分比的度量目标。

1.  我们需要安装 ClusterAutoscaler 并赋予它在 AWS 中更改**Autoscaling Group**（**ASG**）大小的权限。

1.  我们需要通过生成足够的负载来对我们的应用进行压力测试，以便能够扩展应用并导致 HPA 触发集群扩展操作。

我们将使用 Kubernetes Ingress 资源来使用集群外部的流量进行负载测试，以便我们可以创建一个更真实的模拟。

完成后，您将成为 Kubernetes 的船长，所以让我们开始吧：

1.  现在，让我们通过依次运行以下命令来部署`ingress-nginx`设置：

```
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/nginx-0.30.0/deploy/static/mandatory.yaml 
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/nginx-0.30.0/deploy/static/provider/aws/service-l4.yaml 
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/nginx-0.30.0/deploy/static/provider/aws/patch-configmap-l4.yaml 
```

您应该看到以下响应：

![图 15.17：部署 nginx Ingress 控制器](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_15_17.jpg)

图 15.17：部署 nginx Ingress 控制器

1.  现在，让我们获取具有 HA MySQL、Ingress 和 HPA 的应用程序清单：

```
curl -O https://raw.githubusercontent.com/PacktWorkshops/Kubernetes-Workshop/master/Chapter15/Exercise15.02/with_autoscaler.yaml
```

在应用之前，让我们看一下我们的自动缩放触发器：

with_autoscaler.yaml

```
115 apiVersion: autoscaling/v1 
116 kind: HorizontalPodAutoscaler 
117 metadata: 
118   name: counter-hpa 
119 spec: 
120   scaleTargetRef: 
121     apiVersion: apps/v1 
122     kind: Deployment 
123     name: kubernetes-test-ha-application-with-autoscaler-          deployment 
124   minReplicas: 2 
125   maxReplicas: 1000 
126   targetCPUUtilizationPercentage: 10 
```

完整的代码可以在此链接找到：[`packt.live/3bE9v28`](https://packt.live/3bE9v28)。

在这里，我们从此部署的两个副本开始，并允许自己增长到 1000 个副本，同时尝试保持 CPU 利用率恒定在 10％。回想一下，根据我们的 Terraform 模板，我们使用 m4.large EC2 实例来运行这些 Pod。

1.  通过运行以下命令来部署此应用程序：

```
kubectl apply -f with_autoscaler.yaml
```

您应该看到以下响应：

![图 15.18：部署我们的应用程序](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_15_18.jpg)

图 15.18：部署我们的应用程序

1.  有了这个，我们准备进行负载测试。在开始之前，让我们检查一下部署中的 Pod 数量：

```
kubectl describe hpa counter-hpa
```

这可能需要长达 5 分钟才能显示百分比，之后您应该看到类似于这样的东西：

![图 15.19：获取有关我们的 HPA 的详细信息](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_15_19.jpg)

图 15.19：获取有关我们的 HPA 的详细信息

`Deployment pods:`字段显示`2 current / 2 desired`，这意味着我们的 HPA 已将期望的副本计数从 3 更改为 2，因为我们的 CPU 利用率为 0％，低于 10％的目标。

现在，我们需要进行一些负载。我们将从我们的计算机到集群运行一个负载测试，使用 wrk 作为 Docker 容器。但首先，我们需要获取 Ingress 端点以访问我们的集群。

1.  首先运行以下命令以获取您的 Ingress 端点：

```
kubectl get svc ingress-nginx -n ingress-nginx -o jsonpath='{.status.loadBalancer.ingress[0].hostname}'
```

您应该看到以下响应：

![图 15.20：检查我们的 Ingress 端点](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_15_20.jpg)

图 15.20：检查我们的 Ingress 端点

1.  在另一个终端会话中，使用以下命令运行`wrk`负载测试：

```
docker run --rm skandyla/wrk -t10 -c1000 -d600 -H ‚Host: counter.com'  http://YOUR_HOSTNAME/get-number
```

让我们快速了解这些参数：

`-t10`：此测试要使用的线程数，在本例中为 10。

`-c1000`：要保持打开的连接总数。在本例中，每个线程处理 1000 个连接。

`-d600`：运行此测试的秒数（在本例中为 600 秒或 10 分钟）。

您应该获得以下输出：

![图 15.21：对我们的 Ingress 端点运行负载测试](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_15_21.jpg)

图 15.21：对我们的 Ingress 端点运行负载测试

1.  在另一个会话中，让我们留意我们应用程序的 Pod：

```
kubectl get pods --watch
```

您应该能够看到类似于这样的响应：

![图 15.22：观察支持我们应用程序的 Pod](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_15_22.jpg)

图 15.22：观察支持我们应用程序的 Pod

在这个终端窗口中，您应该看到 Pod 数量的增加。请注意，我们也可以在 Grafana 仪表板中检查相同的情况。

在这里，它增加了 1；但很快，这些 Pod 将超出所有可用空间。

1.  在另一个终端会话中，您可以再次设置端口转发到 Grafana 以观察仪表板：

```
kubectl --namespace default port-forward $POD_NAME 3000
```

您应该看到以下响应：

```
Forwarding from 127.0.0.1:3000 -> 3000
Forwarding from [::1]:3000 -> 3000
```

1.  现在，在浏览器上访问`localhost:3000`上的仪表板：![图 15.23：在 Grafana 仪表板中观察我们的集群](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_15_23.jpg)

图 15.23：在 Grafana 仪表板中观察我们的集群

您还应该能够在这里看到 Pod 数量的增加。因此，我们已成功部署了一个自动扩展 Pod 数量的 HPA，随着应用程序负载的增加而增加 Pod 数量。

## ClusterAutoscaler

如果 HPA 确保部署中始终有正确数量的 Pod 在运行，那么当我们的集群对所有这些 Pod 的容量用完时会发生什么？我们需要更多的 Pod，但我们也不希望在不需要时为这些额外的集群容量付费。这就是 ClusterAutoscaler 的作用。

ClusterAutoscaler 将在您的集群内工作，以确保在 ASG（在 AWS 的情况下）中运行的节点数量始终具有足够的容量来运行集群当前部署的应用程序组件。因此，如果部署中的 10 个 Pod 可以放在 2 个节点上，那么当您需要第 11 个 Pod 时，ClusterAutoscaler 将要求 AWS 向您的 Kubernetes 集群添加第 3 个节点以安排该 Pod。当不再需要该 Pod 时，该节点也会消失。让我们看一个简短的架构图，以了解 ClusterAutoscaler 的工作原理：

![图 15.24：节点满负荷的集群](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_15_24.jpg)

图 15.24：节点满负荷的集群

请注意，在此示例中，我们运行了两个工作节点的 EKS 集群，并且所有可用的集群资源都已被占用。因此，ClusterAutoscaler 的作用如下。

当控制平面收到一个无法容纳的 Pod 的请求时，它将保持在`Pending`状态。当 ClusterAutoscaler 观察到这一点时，它将与 AWS EC2 API 通信，并请求 ASG 进行扩展，其中我们的工作节点部署在其中。这需要 ClusterAutoscaler 能够与云提供商的 API 通信，以便更改工作节点计数。在 AWS 的情况下，这还意味着我们要么必须为 ClusterAutoscaler 生成 IAM 凭据，要么允许它使用机器的 IAM 角色来访问 AWS API。

成功的扩展操作应该如下所示：

![图 15.25：额外的节点用于运行额外的 Pod](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_15_25.jpg)

图 15.25：额外的节点用于运行额外的 Pod

我们将在下一个练习中实现 ClusterAutoscaler，然后在随后的活动中进行负载测试。

## 练习 15.03：配置 ClusterAutoscaler

所以，现在我们已经看到我们的 Kubernetes 部署扩展，现在是时候看它扩展到需要向集群添加更多节点容量的地步了。我们将继续上一课的内容，并运行完全相同的应用程序和负载测试，但让它运行更长一点：

1.  要创建 ClusterAutoscaler，首先，我们需要创建一个 AWS IAM 账户，并赋予它管理我们 ASG 的权限。创建一个名为`permissions.json`的文件，内容如下：

```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "autoscaling:DescribeAutoScalingGroups",
        "autoscaling:DescribeAutoScalingInstances",
        "autoscaling:DescribeLaunchConfigurations",
        "autoscaling:SetDesiredCapacity",
        "autoscaling:TerminateInstanceInAutoScalingGroup",
        "autoscaling:DescribeLaunchConfigurations",
        "ec2:DescribeLaunchTemplateVersions",
        "autoscaling:DescribeTags"
      ],
      "Resource": "*"
    }
  ]
}
```

1.  现在，让我们运行以下命令来创建一个 AWS IAM 策略：

```
aws iam create-policy --policy-name k8s-autoscaling-policy --policy-document file://permissions.json
```

您应该看到以下响应：

![图 15.26：创建一个 AWS IAM 策略](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_15_26.jpg)

图 15.26：创建一个 AWS IAM 策略

记下您获得的输出中`Arn:`字段的值。

1.  现在，我们需要创建一个 IAM 用户，然后将策略附加到它。首先，让我们创建用户：

```
aws iam create-user --user-name k8s-autoscaler
```

您应该看到以下响应：

![图 15.27：创建一个 IAM 用户来使用我们的策略](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_15_27.jpg)

图 15.27：创建一个 IAM 用户来使用我们的策略

1.  现在，让我们将 IAM 策略附加到用户：

```
aws iam attach-user-policy --policy-arn <ARN_VALUE> --user-name k8s-autoscaler
```

使用您在*步骤 2*中获得的 ARN 值。

1.  现在，我们需要这个 IAM 用户的秘密访问密钥。运行以下命令：

```
aws iam create-access-key --user-name k8s-autoscaler
```

您应该得到以下响应：

![图 15.28：获取创建的 IAM 用户的秘密访问密钥](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_15_28.jpg)

图 15.28：获取创建的 IAM 用户的秘密访问密钥

在此命令的输出中，请注意`AccessKeyId`和`SecretAccessKey`。

1.  现在，获取我们提供的 ClusterAutoscaler 的清单文件：

```
curl -O https://raw.githubusercontent.com/PacktWorkshops/Kubernetes-Workshop/master/Chapter15/Exercise15.03/cluster_autoscaler.yaml
```

1.  我们需要创建一个 Kubernetes Secret 来将这些凭据暴露给 ClusterAutoscaler。打开`cluster_autoscaler.yaml`文件。在第一个条目中，您应该看到以下内容：

cluster_autoscaler.yaml

```
1  apiVersion: v1
2  kind: Secret
3  metadata:
4    name: aws-secret
5    namespace: kube-system
6  type: Opaque
7  data:
8    aws_access_key_id: YOUR_AWS_ACCESS_KEY_ID
9    aws_secret_access_key: YOUR_AWS_SECRET_ACCESS_KEY
```

您可以在此链接找到完整的代码：[`packt.live/2DCDfzZ`](https://packt.live/2DCDfzZ)。

您需要使用 AWS 在*步骤 5*中返回的值的 Base64 编码版本替换`YOUR_AWS_ACCESS_KEY_ID`和`YOUR_AWS_SECRET_ACCESS_KEY`。

1.  要以 Base64 格式编码，运行以下命令：

```
echo -n <YOUR_VALUE> | base64
```

运行两次，使用`AccessKeyID`和`SecretAccessKey`替换`<YOUR_VALUE>`，以获取相应的 Base64 编码版本，然后将其输入到 secret 字段中。完成后应如下所示：

```
aws_access_key_id: QUtJQUlPU0ZPRE5ON0VYQU1QTEUK
aws_secret_access_key: d0phbHJYVXRuRkVNSS9LN01ERU5HL2JQeFJmaUNZRVhBTVBMRUtFWQo=
```

1.  现在，在相同的`cluster_autoscaler.yaml`文件中，转到第 188 行。您需要将`YOUR_AWS_REGION`的值替换为您部署 EKS 集群的区域的值，例如`us-east-1`：

集群自动缩放器.yaml

```
176   env: 
177   - name: AWS_ACCESS_KEY_ID 
178     valueFrom: 
179       secretKeyRef: 
180         name: aws-secret 
181         key: aws_access_key_id 
182   - name: AWS_SECRET_ACCESS_KEY 
183     valueFrom: 
184       secretKeyRef: 
185         name: aws-secret 
186         key: aws_secret_access_key 
187   - name: AWS_REGION 
188     value: <YOUR_AWS_REGION>
```

您可以在此链接找到整个代码：[`packt.live/2F8erkb`](https://packt.live/2F8erkb)。

1.  现在，通过运行以下命令应用此文件：

```
kubectl apply -f cluster_autoscaler.yaml
```

您应该看到类似以下的响应：

![图 15.29：部署我们的 ClusterAutoscaler](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_15_29.jpg)

图 15.29：部署我们的 ClusterAutoscaler

1.  请注意，我们现在需要修改 AWS 中的 ASG 以允许扩展；否则，ClusterAutoscaler 将不会尝试添加任何节点。为此，我们提供了一个修改过的`main.tf`文件，只更改了一行：`max_size = 5`（*第 299 行*）。这将允许集群最多添加五个 EC2 节点到自身。

导航到您下载了先前 Terraform 文件的相同位置，然后运行以下命令：

```
curl -O https://raw.githubusercontent.com/PacktWorkshops/Kubernetes-Workshop/master/Chapter15/Exercise15.03/main.tf
```

您应该看到以下响应：

![图 15.30：下载修改后的 Terraform 文件](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_15_30.jpg)

图 15.30：下载修改后的 Terraform 文件

1.  现在，将修改应用到 Terraform 文件：

```
terraform apply
```

验证更改仅应用于 ASG 的最大容量，然后在提示时输入`yes`：

![图 15.31：应用我们的 Terraform 修改](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_15_31.jpg)

图 15.31：应用我们的 Terraform 修改

注意

我们将在以下活动中测试此 ClusterAutoscaler。因此，现在不要删除您的集群和 API 资源。

在这一点上，我们已经部署了我们的 ClusterAutoscaler，并配置它以访问 AWS API。因此，我们应该能够根据需要扩展节点的数量。

让我们继续进行下一个活动，在那里我们将对我们的集群进行负载测试。您应该尽快进行此活动，以便降低成本。

## 活动 15.01：使用 ClusterAutoscaler 对我们的集群进行自动扩展

在这个活动中，我们将运行另一个负载测试，这一次，我们将运行更长时间，并观察基础架构的变化，因为集群扩展以满足需求。这个活动应该重复之前的步骤（如*练习 15.02，在 Kubernetes 中扩展工作负载*中所示）来运行负载测试，但这一次，应该安装 ClusterAutoscaler，这样当您的集群对 Pod 的容量不足时，它将扩展节点的数量以适应新的 Pod。这样做的目的是看到负载测试增加节点数量。

按照以下指南完成您的活动：

1.  我们将使用 Grafana 仪表板来观察集群指标，特别关注运行中的 Pod 数量和节点数量。

1.  我们的 HPA 应该设置好，这样当我们的应用程序接收到更多负载时，我们可以扩展 Pod 的数量以满足需求。

1.  确保您的 ClusterAutoscaler 已成功设置。

注意

为了满足前面提到的三个要求，您需要成功完成本章中的所有练习。我们将使用在这些练习中创建的资源。

1.  运行负载测试，如*练习 15.02*的*步骤 2*所示。如果愿意，您可以选择更长或更强烈的测试。

在完成此活动时，您应该能够通过描述 AWS ASG 来观察节点数量的增加，如下所示：

![图 15.32：观察到节点数量的增加通过描述 AWS 扩展组](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_15_32.jpg)

图 15.32：通过描述 AWS 扩展组观察节点数量的增加

您还应该能够在 Grafana 仪表板中观察到相同的情况：

![图 15.33：在 Grafana 仪表板中观察到节点数量的增加](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_15_33.jpg)

图 15.33：在 Grafana 仪表板中观察到节点数量的增加

注意

此活动的解决方案可在以下地址找到：[`packt.live/304PEoD`](https://packt.live/304PEoD)。确保通过运行命令`terraform destroy`删除 EKS 集群。

## 删除您的集群资源

这是我们将使用 EKS 集群的最后一章。因此，我们建议您使用以下命令删除您的集群资源：

```
terraform destroy
```

这应该停止使用 Terraform 创建的 EKS 集群的计费。

# 总结

让我们稍微回顾一下我们从*第十一章*《构建自己的 HA 集群》开始讨论如何以高可用的方式运行 Kubernetes 所走过的路程。我们讨论了如何设置一个安全的生产集群，并使用 Terraform 等基础设施即代码工具创建，以及保护其运行的工作负载。我们还研究了必要的修改，以便良好地扩展我们的应用程序——无论是有状态的还是无状态的版本。

然后，在本章中，我们看了如何使用数据来扩展我们的应用程序运行时，特别是在引入 Prometheus、Grafana 和 Kubernetes Metrics 服务器时。然后，我们利用这些信息来利用 HPA 和 ClusterAutoscaler，以便我们可以放心地确保我们的集群始终具有适当的大小，并且可以自动响应需求的激增，而无需支付过度配置的硬件。

在接下来的一系列章节中，我们将探索 Kubernetes 中的一些高级概念，从下一章开始介绍准入控制器。


# 第十六章： Kubernetes 准入控制器

概述

在本章中，我们将学习 Kubernetes 准入控制器，并使用它们来修改或验证传入的 API 请求。本章描述了 Kubernetes 准入控制器的实用性，以及它们如何扩展您的 Kubernetes 集群的功能。您将了解几个内置的准入控制器，以及变异和验证控制器之间的区别。在本章结束时，您将能够创建自己的自定义准入控制器，并将这些知识应用于构建适合您所需场景的控制器。

# 介绍

在*第四章*中，*如何与 Kubernetes（API 服务器）通信*，我们学习了 Kubernetes 如何将其**应用程序编程接口**（**API**）暴露出来，以便与 Kubernetes 平台进行交互。您还学习了如何使用 kubectl 来创建和管理各种 Kubernetes 对象。 kubectl 工具只是 Kubernetes API 服务器的客户端。 Kubernetes 主节点托管 API 服务器，通过它任何人都可以与集群通信。 API 服务器不仅为外部参与者提供了与 Kubernetes 通信的方式，还为所有内部组件（例如运行在工作节点上的 kubelet）提供了通信的方式。

API 服务器是我们集群的中央访问点。如果我们想确保我们组织的默认最佳实践和策略得到执行，那么检查和应用它们的最佳地方就是在 API 服务器上。 Kubernetes 通过**准入控制器**提供了这种能力。

让我们花点时间来了解为什么准入控制器很有用。例如，假设我们有一个标准的标签集策略，用于在所有对象中协助报告每个业务单元的对象组。这对于获取特定数据可能很重要，例如集成团队正在执行多少个 Pod。如果我们根据它们的标签来管理和监控对象，那么没有所需标签的对象可能会妨碍我们的管理和监控实践。因此，我们希望实施一个策略，如果对象规范中未定义这些标签，则将阻止创建对象。这个要求可以很容易地通过准入控制器来实现。

注意

Open Policy Agent 是一个很好的例子，展示了如何使用 webhooks 来构建一个可扩展的平台，以在 Kubernetes 对象上应用标准。您可以在此链接找到更多详细信息：[`www.openpolicyagent.org/docs/latest/kubernetes-admission-control`](https://www.openpolicyagent.org/docs/latest/kubernetes-admission-control)。

准入控制器是一组组件，拦截所有对 Kubernetes API 服务器的调用，并提供一种确保任何请求都符合所需标准的方法。重要的是要注意，这些控制器在 API 调用经过身份验证和授权后被调用，而在对象被操作和存储在 etcd 之前被调用。这提供了一个完美的机会来实施控制和治理，应用标准，并接受或拒绝 API 请求，以保持集群的期望状态。让我们来看看准入控制器在 Kubernetes 集群中是如何工作的。

# 准入控制器的工作原理

Kubernetes 提供了一组超过 25 个准入控制器。一组准入控制器默认启用，集群管理员可以向 API 服务器传递标志来控制启用/禁用其他控制器（配置生产级集群中的 API 服务器超出了本书的范围）。这些可以大致分为两种类型：

+   **变异准入控制器**允许您在应用到 Kubernetes 平台之前修改请求。`LimitRanger`就是一个例子，如果 Pod 本身未定义，则将`defaultRequests`应用于 Pod。

+   **验证准入控制器**验证请求，不能更改请求对象。如果此控制器拒绝请求，Kubernetes 平台将不会执行该请求。一个例子是`NamespaceExists`控制器，如果请求中引用的命名空间不可用，则会拒绝该请求。

基本上，准入控制器分为两个阶段执行。在第一阶段，执行变异准入控制器，在第二阶段，执行验证准入控制器。

注意

根据情况，最好避免使用变异控制器，因为它们会改变请求的状态，调用者可能不知道这些变化。相反，您可以使用验证控制器来拒绝无效的请求，并让调用者修复请求。

准入控制器的高级概述如下图所示：

![图 16.1：创建对象的 API 请求的阶段](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_16_01.jpg)

图 16.1：创建对象的 API 请求的阶段

当 Kubernetes API 服务器接收到 API 调用（可以通过 kubectl 或在其他节点上运行的 kubelet 进行调用），它会将调用通过以下阶段：

1.  执行调用的身份验证和授权，以确保调用者已经过身份验证并应用了 RBAC 策略。

1.  将有效负载通过所有现有的变异控制器。变异控制器是可以更改客户端发送的对象的控制器。

1.  检查对象是否符合定义的模式，以及所有字段是否有效。

1.  将有效负载通过所有现有的验证控制器。这些控制器验证最终对象。

1.  将对象存储在 etcd 数据存储中。

从*图 16.1*可以看出，一些准入控制器附有称为**webhooks**的东西。这可能并非所有准入控制器都是如此。我们将在本章的后面部分了解更多关于 webhooks 的内容。

请注意，一些控制器既提供变异功能，也提供验证功能。实际上，一些 Kubernetes 功能是作为准入控制器实现的。例如，当 Kubernetes 命名空间进入终止状态时，`NamespaceLifecycle`准入控制器会阻止在终止命名空间中创建新对象。

注意

出于简洁起见，本章只涵盖了一些准入控制器。请参考此链接，了解可用的控制器的完整列表：[`kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#what-does-each-admission-controller-do`](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#what-does-each-admission-controller-do)。

让我们确认我们的 Minikube 设置已配置为运行准入控制器。运行以下命令以启动 Minikube，并启用所有必需的插件：

```
minikube stop
minikube start --extra-config=apiserver.enable-admission-plugins="LimitRanger,NamespaceExists,NamespaceLifecycle,ResourceQuota,ServiceAccount,DefaultStorageClass,MutatingAdmissionWebhook,ValidatingAdmissionWebhook"
```

您应该看到类似以下截图的响应：

![图 16.2：启动 Minikube 并启用所有必需的插件运行准入控制器](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_16_02.jpg)

图 16.2：启动 Minikube 并启用所有必需的插件以运行准入控制器

现在我们已经概述了内置准入控制器，让我们看看如何使用我们自己的自定义逻辑创建一个准入控制器。

# 创建具有自定义逻辑的控制器

如前所述，Kubernetes 提供了一系列具有预定义功能的控制器。这些控制器已经内置到 Kubernetes 服务器二进制文件中。但是，如果您需要拥有自己的策略或标准来进行检查，并且没有一个准入控制器符合您的要求，会发生什么呢？

为了满足这样的需求，Kubernetes 提供了称为**准入 Webhook**的东西。准入 Webhook 有两种类型，我们将在以下部分进行学习。

## 变更准入 Webhook

**变更准入 Webhook**是一种变更准入控制器，它本身没有任何逻辑。相反，它允许您定义一个 URL，Kubernetes API 服务器将调用该 URL。这个 URL 就是我们 Webhook 的地址。从功能上讲，Webhook 是一个接受请求、处理请求，然后做出响应的 HTTPS 服务器。

如果定义了多个 URL，则它们将按链式处理，即第一个 Webhook 的输出将成为第二个 Webhook 的输入。

Kubernetes API 服务器将一个负载（AdmissionReview 对象）发送到 Webhook URL，请求正在处理中。您可以根据需要修改请求（例如，添加自定义注释）并发送回修改后的请求。Kubernetes API 服务器将在创建资源的下一个阶段使用修改后的对象。

执行流程将如下：

1.  Kubernetes API 接收到创建对象的请求。例如，假设您想创建一个如下所定义的 Pod：

```
apiVersion: v1
kind: Pod
metadata:
  name: configmap-env-pod
spec:
  containers:
    - name: configmap-container
      image: k8s.gcr.io/busybox
      command: [ "/bin/sh", "-c", "sleep 5" ]
```

1.  Kubernetes 调用一个名为`MutatingAdmissionWebHook`的 Webhook，并将对象定义传递给它。在这种情况下，它是 Pod 规范。

1.  Webhook（由您编写的自定义代码）接收对象并根据自定义规则进行修改。例如，它添加自定义注释`podModified="true"`。修改后，对象将如下所示：

```
apiVersion: v1
kind: Pod
metadata:
  name: configmap-env-pod
  annotations:
    podModified: "true"
spec:
  containers:
    - name: configmap-container
      image: k8s.gcr.io/busybox
      command: [ "/bin/sh", "-c", "sleep 5" ]
```

1.  Webhook 返回修改后的对象。

1.  Kubernetes 将修改后的对象视为原始请求并继续进行。

前面提到的流程可以可视化如下。请注意，该流程经过简化，以便您理解主要阶段：

![图 16.3：变更准入 Webhook 的流程](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_16_03.jpg)

图 16.3：变异入场 Webhook 的流程

## 验证入场 Webhook

第二种类型的 Webhook 是验证入场 Webhook。这个钩子与变异入场 Webhook 类似，没有自己的逻辑。按照相同的模式，它允许我们定义一个 URL，最终提供决定接受或拒绝此调用的逻辑。

主要区别在于验证 Webhook 不能修改请求，只能允许或拒绝请求。如果此 Webhook 拒绝请求，Kubernetes 将向调用者发送错误；否则，它将继续执行请求。

# Webhook 的工作原理

Webhook 部署为 Kubernetes 集群中的 Pod，并且 Kubernetes API 服务器使用 AdmissionReview 对象通过 SSL 调用它们。该对象定义 AdmissionRequest 和 AdmissionResponse 对象。Webhook 从 AdmissionRequest 对象中读取请求有效负载，并在 AdmissionResponse 对象中提供成功标志和可选更改。

以下是 AdmissionReview 对象的顶级定义。请注意，AdmissionRequest 和 AdmissionResponse 都是 AdmissionReview 对象的一部分。以下是 Kubernetes 源代码中 AdmissionReview 对象定义的摘录：

```
// AdmissionReview describes an admission review request/response.
type AdmissionReview struct {
    metav1.TypeMeta `json:",inline"`
    // Request describes the attributes for the admission request.
    // +optional
    Request *AdmissionRequest `json:"request,omitempty"       protobuf:"bytes,1,opt,name=request"`
    // Response describes the attributes for the admission response.
    // +optional
    Response *AdmissionResponse `json:"response,omitempty" protobuf:"bytes,2,opt,name=response"`
}
```

注意

此片段是从 Kubernetes 源代码中提取的。您可以在此链接查看 AdmissionReview 对象的更多详细信息：[`github.com/kubernetes/api/blob/release-1.16/admission/v1beta1/types.go`](https://github.com/kubernetes/api/blob/release-1.16/admission/v1beta1/types.go)。

相同的 AdmissionReview 对象用于变异和验证入场 Webhook。变异 Webhook 计算满足 Webhook 中编码的自定义要求所需的更改。这些更改（定义为补丁）与 AdmissionResponse 对象中的`patchType`字段一起传递到`patch`字段中。然后 API 服务器将该补丁应用于原始对象，并将结果对象持久化在 API 服务器中。要验证 Webhook，这两个字段保持为空。

验证入场 Webhook 只需设置一个标志以接受或拒绝请求，而变异入场 Webhook 将设置一个标志，指示请求是否已根据请求成功修改。

首先，让我们更仔细地看一下如何手动修补一个对象，这将帮助您构建一个可以修补对象的 Webhook。

您可以使用`kubectl patch`命令手动打补丁一个对象。例如，假设您想在对象的`.metadata.annotation`部分添加一个字段。命令将如下所示：

```
kubectl patch configmap simple-configmap -n webhooks -p '{"metadata": {"annotations":  {"new":"annotation"}  } }'
```

请注意我们要添加的字段之前和之后的双空格（在前面的命令中显示为`{"new":"annotation"}`）。让我们在一个练习中实现这个，并学习如何使用 JSON 负载来使用这个命令。

## 练习 16.01：通过补丁修改 ConfigMap 对象

在这个练习中，我们将使用 kubectl 打补丁一个 ConfigMap。我们将向 ConfigMap 对象添加一个注释。这个注释以后可以用来对对象进行分组，类似于我们在*介绍*部分提到的用例。因此，如果多个团队在使用一个集群，我们希望跟踪哪些团队在使用哪些资源。让我们开始练习：

1.  创建一个名为`webhooks`的命名空间：

```
kubectl create ns webhooks
```

您应该看到以下响应：

```
namespace/webhooks created
```

1.  接下来，使用以下命令创建一个 ConfigMap：

```
kubectl create configmap simple-configmap --from-literal=url=google.com -n webhooks
```

您将看到以下响应：

```
configmap/simple-configmap created
```

1.  使用以下命令检查 ConfigMap 的内容：

```
kubectl get configmap simple-configmap -o yaml -n webhooks
```

您应该看到以下响应：

![图 16.4：以 YAML 格式获取 ConfigMap 的内容](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_16_04.jpg)

图 16.4：以 YAML 格式获取 ConfigMap 的内容

1.  现在，让我们用一个注释来打补丁 ConfigMap。我们要添加的注释是`teamname`，值为`kubeteam`：

```
kubectl patch configmap simple-configmap -n webhooks -p '{"metadata": {"annotations":  {"teamname":"kubeteam"}  } }'
```

您将得到以下响应：

```
configmap/simple-configmap patched
```

在*第六章*，*标签和注释*中，我们学到注释被存储为键值对。因此，一个键只能有一个值，如果一个键已经存在值（在这种情况下是`teamname`），那么新值将覆盖旧值。因此，请确保您的 webhook 逻辑排除已经具有所需配置的对象。

1.  现在，让我们使用详细的补丁说明来应用另一个补丁，使用 JSON 格式提供所需的字段：

```
kubectl patch configmap simple-configmap -n webhooks --type='json' -p='[{"op": "add", "path": "/metadata/annotations/custompatched", "value": "true"}]'
```

请注意补丁的三个组成部分：`op`（用于操作，如`add`），`path`（用于要打补丁的字段的位置），和`value`（这是新值）。您应该看到以下响应：

```
configmap/simple-configmap patched
```

这是另一种应用补丁的方式。您可以看到前面的命令，它指示 Kubernetes 添加一个新的注释，键为`custompatched`，值为`true`。

1.  现在，让我们看看补丁是否已经应用。使用以下命令：

```
kubectl get configmap simple-configmap -n webhooks -o yaml
```

您应该看到以下输出：

![图 16.5：检查我们的 ConfigMap 上修改的注释](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_16_05.jpg)

图 16.5：检查我们的 ConfigMap 上修改的注释

正如您从 `metadata` 下的 `annotations` 字段中所看到的，这两个注释都已应用到我们的 ConfigMap 上。平台团队现在知道谁拥有这个 ConfigMap 对象。

## 构建变更 Admission WebHook 的指南

我们现在知道了工作中变更 Admission WebHook 的所有部分。请记住，Webhook 只是一个简单的 HTTPS 服务器，您可以使用自己选择的语言编写它。Webhook 被部署为 Pod 在集群中。Kubernetes API 服务器将通过 SSL 在端口 443 上调用这些 Pod 来变更或验证对象。

构建 Webhook Pod 的伪代码将如下所示：

1.  在 Pod 中设置一个简单的 HTTPS 服务器（Webhook）来接受 POST 调用。请注意，调用必须通过 SSL 进行。

1.  Kubernetes 将通过 HTTPS POST 调用将 AdmissionReview 对象发送到 Webhook。

1.  Webhook 代码将处理 AdmissionRequest 对象，以获取请求中对象的详细信息。

1.  Webhook 代码将可选择地修补对象并将响应标志设置为指示成功或失败。

1.  Webhook 代码将使用更新后的请求填充 AdmissionReview 对象中的 AdmissionResponse 部分。

1.  Webhook 将使用 AdmissionReview 对象回应 POST 调用（在 *步骤 2* 中收到）。

1.  Kubernetes API 服务器将评估响应，并根据标志接受或拒绝客户端请求。

在 Webhook 的代码中，我们将使用 JSON 指定路径和所需的修改。请记住，从之前的练习中，我们的修补对象定义将包含以下内容：

+   `op` 指定操作，比如 `add` 和 `replace`。

+   `path` 指定我们要修改的字段的位置。参考 *图 16.5* 中命令的输出，并注意不同的字段位于不同的位置。例如，名称位于 metadata 字段内，因此其路径将是 `/metadata/name`。

+   `value` 指定字段的值。

用 Go 编写的简单变更 Webhook 应该如下所示：

mutatingcontroller.go

```
20 func MutateCustomAnnotation(admissionRequest      *v1beta1.AdmissionRequest ) (*v1beta1.AdmissionResponse,      error){ 
21 
22   // Parse the Pod object. 
23   raw := admissionRequest.Object.Raw 
24   pod := corev1.Pod{} 
25   if _, _, err := deserializer.Decode(raw, nil, &pod); err !=        nil{ 
26         return nil, errors.New("unable to parse pod") 
27   } 
28 
29   //create annotation to add 
30   annotations := map[string]string{"podModified" : "true"} 
31 
32   //prepare the patch to be applied to the object 
33   var patch []patchOperation 
34   patch = append(patch, patchOperation{ 
35         Op:   "add", 
36         Path: "/metadata/annotations", 
37         Value: annotations, 
38   }) 
39 
40   //convert patch into bytes 
41   patchBytes, err := json.Marshal(patch) 
42   if err != nil { 
43         return nil, errors.New("unable to parse the patch") 
44   } 
45 
46   //create the response with patch bytes 
47   var admissionResponse *v1beta1.AdmissionResponse 
48   admissionResponse = &v1beta1.AdmissionResponse { 
49         Allowed: true, 
50         Patch:   patchBytes, 
51         PatchType: func() *v1beta1.PatchType { 
52              pt := v1beta1.PatchTypeJSONPatch 
53              return &pt 
54         }(), 
55   } 
56 
57   //return the response 
58   return admissionResponse, nil 
59 
60 } 
```

此示例的完整代码可以在 [`packt.live/2GFRCot`](https://packt.live/2GFRCot) 找到。

正如您在前面的代码中所看到的，三个主要部分是 **AdmissionRequest** 对象，**patch**，以及带有修补信息的 **AdmissionResponse** 对象。

到目前为止，在本章中，我们已经学习了什么是准入 webhook，以及它如何与 Kubernetes API 服务器交互。我们还演示了通过使用补丁来更改请求的对象的一种方法。现在，让我们应用我们到目前为止学到的知识，在我们的 Kubernetes 集群中部署一个 webhook。

请记住，API 服务器和 webhook 之间的所有通信都是通过 SSL 进行的。SSL 是一种用于网络安全通信的协议。为了做到这一点，我们需要创建公钥和私钥，正如你将在接下来的练习中看到的。

请注意，我们还没有构建进入 webhook 的代码。首先，让我们演示如何部署用于 webhook 的 Pods（使用 Deployment）使用预构建的容器，然后我们将继续构建进入 Pod 的代码，使 webhook 运行起来。

## 练习 16.02：部署 Webhook

在这个练习中，我们将在 Kubernetes 中部署一个简单的预构建 webhook 服务器。请记住，webhook 只是一个 HTTPS 服务器，这正是我们要创建的。当 Kubernetes 需要通过 SSL 调用 webhook 端点时，我们需要为我们的调用创建一个证书。一旦我们为 SSL 通信创建了证书，我们将使用 Kubernetes Deployment 对象来部署我们的 webhook：

1.  创建一个自签名证书的**证书颁发机构**（**CA**）。这个 CA 将稍后用于在 Kubernetes 和我们的 webhook 服务器之间创建 HTTPS 调用的信任：

```
openssl req -nodes -new -x509 -keyout controller_ca.key -out controller_ca.crt -subj "/CN=Mutating Admission Controller Webhook CA"
```

这应该给你以下的回应：

![图 16.6：生成自签名证书](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_16_06.jpg)

图 16.6：生成自签名证书

注意

您可以在此链接了解更多关于自签名证书的信息：[`aboutssl.org/what-is-self-sign-certificate/`](https://aboutssl.org/what-is-self-sign-certificate/)。

1.  为 SSL 调用创建私钥：

```
openssl genrsa -out tls.key 2048
```

你应该会看到以下的回应：

![图 16.7：为 SSL 调用创建私钥](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_16_07.jpg)

图 16.7：为 SSL 调用创建私钥

1.  现在用 CA 签署服务器证书：

```
openssl req -new -key tls.key -subj "/CN=webhook-server.webhooks.svc" \
    | openssl x509 -req -CA controller_ca.crt -CAkey controller_ca.key -CAcreateserial -out tls.crt
```

请注意，此命令中服务的名称是将在集群中公开我们的 webhook 的服务，以便 API 服务器可以访问它。我们将在*步骤 7*中重新访问这个名称。你应该会看到以下的回应：

```
Signature ok
subject=/CN=webhook-server.webhooks.svc
Getting CA Private Key
```

1.  现在我们已经创建了一个我们的服务器可以使用的证书。接下来，我们将创建一个 Kubernetes Secret，将私钥和证书加载到我们的 webhook 服务器中：

```
kubectl -n webhooks create secret tls webhook-server-tls \
    --cert "tls.crt" \
    --key "tls.key"
```

您应该看到以下响应：

```
secret/webhook-server-tls created
```

1.  我们的 webhook 将作为一个 Pod 运行，我们将使用部署来创建它。为此，首先创建一个名为`mutating-server.yaml`的文件，其中包含以下内容：

```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: webhook-server
  labels:
    app: webhook-server
spec:
  replicas: 1
  selector:
    matchLabels:
      app: webhook-server
  template:
    metadata:
      labels:
        app: webhook-server
    spec:
      containers:
      - name: server
        image: packtworkshops/the-kubernetes-          workshop:mutating-webhook
        imagePullPolicy: Always
        ports:
        - containerPort: 8443
          name: webhook-api
        volumeMounts:
        - name: webhook-tls-certs
          mountPath: /etc/secrets/tls
          readOnly: true
      volumes:
      - name: webhook-tls-certs
        secret:
          secretName: webhook-server-tls
```

请注意，我们正在链接到我们提供的服务器的预制图像。

1.  使用我们在上一步中创建的 YAML 文件创建部署：

```
kubectl create -f mutating-server.yaml -n webhooks
```

您应该看到以下响应：

```
deployment.apps/webhook-server created
```

1.  创建服务器后，我们需要创建一个 Kubernetes 服务。请注意，服务可以通过`webhook-server.webhooks.svc`访问。这个字符串是我们在*步骤 3*中创建证书时使用的，它基于以下规范中定义的字段，格式为`<SERVICENAME>.<NAMESPACENAME>.svc`。

创建一个名为`mutating-serversvc.yaml`的文件，以定义具有以下规范的服务：

```
apiVersion: v1
kind: Service
metadata:
  labels:
    app: webhook-server
  name: webhook-server
  namespace: webhooks
spec:
  ports:
  - port: 443
    protocol: TCP
    targetPort: 8443
  selector:
    app: webhook-server
  sessionAffinity: None
  type: ClusterIP
```

1.  使用上一步的定义，使用以下命令创建服务：

```
kubectl create -f mutating-serversvc.yaml -n webhooks
```

您应该看到以下响应：

```
service/webhook-server created
```

在这个练习中，我们部署了一个预构建的 webhook，并配置了证书，使得我们的 webhook 准备好接受来自 Kubernetes API 服务器的调用。

## 配置 Webhook 以与 Kubernetes 一起工作

在这个阶段，我们已经使用部署创建并部署了 webhook。现在，我们需要向 Kubernetes 注册 webhook，以便 Kubernetes 知道它。这样做的方法是创建一个`MutatingWebHookConfiguration`对象。

注意

您可以在[`kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/`](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/)找到有关 MutatingConfigurationWebhook 的更多详细信息。

以下片段显示了`MutatingWebhookConfiguration`的配置对象的示例：

```
apiVersion: admissionregistration.k8s.io/v1beta1
kind: MutatingWebhookConfiguration
metadata:
  name: pod-annotation-webhook
webhooks:
- name: webhook-server.webhooks.svc
   clientConfig:
     service:
       name: webhook-server
       namespace: webhooks
       path: "/mutate"
     caBundle: "LS0…"    #The caBundle is truncated for brevity
   rules:
     - operations: [ "CREATE" ]
       apiGroups: [""]
       apiVersions: ["v1"]
       resources: ["pods"]
```

以下是前述对象中的一些值得注意的定义：

1.  `clientConfig.service`部分定义了变异 webhook 的位置（我们在*练习 16.02*中部署的*部署 webhook*）。

1.  `caBundle`部分包含 SSL 信任将建立的证书。这是以 Base64 格式编码的证书。我们将在下一节中解释如何对其进行编码。

1.  `rules`部分定义了需要拦截的操作。在这里，我们指示 Kubernetes 拦截任何创建新 Pod 的调用。

## 如何以 Base64 格式编码证书

如前所述，当 Kubernetes API 服务器调用 webhook 时，调用是通过 SSL 加密的，我们需要在 webhook 定义中提供 SSL 信任证书。这可以在前一节中显示的`MutatingWebhookConfiguration`定义中的`caBundle`字段中看到。该字段中的数据是 Base64 编码的，正如您在*第十章*，*ConfigMaps 和 Secrets*中学到的。以下命令可用于将证书编码为 Base64 格式。

首先，使用以下命令将生成的文件转换为 Base64 格式：

```
openssl base64 -in controller_ca.crt -out controller_ca-base64.crt
```

由于我们需要将生成的 CA 捆绑包转换为 Base64 格式并放入 YAML 文件中（如前所述），我们需要删除换行符（`\n`）字符。可以使用以下命令来执行此操作：

```
cat controller_ca-base64.crt | tr -d '\n' > onelinecert.pem
```

这两个命令在成功执行后不会在终端上显示任何响应。在这个阶段，您将在`onelinecert.pem`文件中拥有 CA 捆绑包，您可以复制它来创建您的 YAML 定义。

## Activity 16.01：创建一个可变的 Webhook，向 Pod 添加注释

在这个活动中，我们将利用我们在本章和之前章节中所学到的知识来创建一个可变的 webhook，它会向 Pod 添加一个自定义注释。这样的 webhook 可能有许多用例。例如，您可能希望记录容器镜像是否来自先前批准的存储库，以供将来报告。进一步扩展，您还可以在不同的节点上从不同的存储库调度 Pods。

完成此活动的高级步骤如下：

1.  创建一个名为`webhooks`的新命名空间。如果已经存在，则删除现有的命名空间，然后再次创建它。

1.  生成自签名的 CA 证书。

1.  为 SSL 生成私钥/公钥对并使用 CA 证书进行签名。

1.  创建一个保存在先前步骤中生成的私钥/公钥对的密钥。

1.  编写 webhook 代码以在 Pod 中添加自定义注释。

1.  将 webhook 服务器代码打包为 Docker 容器。

1.  将 Docker 容器推送到您选择的公共存储库。

注意

如果您在构建自己的 webhook 时遇到任何困难，可以使用此链接中提供的代码作为参考：[`packt.live/2R1vJlk`](https://packt.live/2R1vJlk)。

如果你想避免构建和打包 webhook，我们提供了一个预构建的容器，这样你就可以直接在你的部署中使用它。你可以从 Docker Hub 使用这个图像：`packtworkshops/the-kubernetes-workshop:webhook`。

使用此图像可以跳过*步骤 5*至*7*。

1.  创建一个部署，部署 webhook 服务器。

1.  将 webhooks 部署公开为 Kubernetes 服务。

1.  创建 CA 证书的 Base64 编码版本。

1.  创建一个`MutatingWebHookConfiguration`对象，以便 Kubernetes 可以拦截 API 调用并调用我们的 webhook。

在这个阶段，我们的 webhook 已经创建。现在，为了测试我们的 webhook 是否工作，创建一个没有注释的简单 Pod。

一旦 Pod 被创建，确保通过描述它来添加注释到 Pod。这里是预期输出的截断版本。请注意，这里的注释应该是由我们的 webhook 添加的：

![图 16.8：活动 16.01 的预期输出](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_16_08.jpg)

图 16.8：活动 16.01 的预期输出

注意

此活动的解决方案可在第 799 页找到。

# 验证 Webhook

我们已经了解到，变异 webhook 基本上允许修改 Kubernetes 对象。另一种 webhook 称为验证 webhook。顾名思义，这个 webhook 不允许对 Kubernetes 对象进行任何更改；相反，它作为我们集群的守门人。它允许我们编写代码，可以验证任何被请求的 Kubernetes 对象，并根据我们指定的条件允许或拒绝请求。

让我们通过一个例子来了解这如何有帮助。假设我们的 Kubernetes 集群被许多团队使用，我们想知道哪些 Pod 与哪些团队相关联。一个解决方案是要求所有团队在其 Pod 上添加一个标签（例如，键为`teamName`，值为团队名称）。正如你所猜测的那样，强制执行一组标签不是标准的 Kubernetes 功能。在这种情况下，我们需要创建自己的逻辑来禁止没有这些标签的 Pod。

实现这一点的一种方法是编写一个验证 webhook，查找任何 Pod 请求中的此标签，并拒绝创建请求的 Pod，如果此标签不存在。您将在本章后面的*活动 16.02*中做到这一点，*创建一个验证 webhook，检查 Pod 中是否存在标签*。现在，让我们看一下验证 webhook 的代码将是什么样子。

## 编写一个简单的验证 WebHook

让我们来看一段简单验证 webhook 代码的摘录：

```
func ValidateTeamAnnotation(admissionRequest   *v1beta1.AdmissionRequest ) (*v1beta1.AdmissionResponse, error){
      // Get the AdmissionReview Object
      raw := admissionRequest.Object.Raw
      pod := corev1.Pod{}

     // Parse the Pod object.
      if _, _, err := deserializer.Decode(raw, nil, &pod);         err != nil {
            return nil, errors.New("unable to parse pod")
      }
      //Get all the Labels of the Pod
      podLabels := pod.ObjectMeta.GetLabels()

      //Logic to check if label exists
      //check if the teamName label is available, if not         generate an error.
      if podLabels == nil || podLabels[teamNameLabel] == "" {
           return nil, errors.New("teamName label not found")
      }

      //Populate the Allowed flag
      //if the teamName label exists, return the response with 
      //Allowed flag set to true.
      var admissionResponse *v1beta1.AdmissionResponse
      admissionResponse = &v1beta1.AdmissionResponse {
           Allowed: true,
      }
      //Return the response with Allowed set to true
      return admissionResponse, nil
}
const (
      //This is the name of the label that is expected to be         part of the pods to allow them to be created.
      teamNameLabel = `teamName`
)
```

您可以在此片段中观察到的三个主要部分是 AdmissionRequest 对象，检查标签是否存在的逻辑，以及使用 Allowed 标志创建 AdmissionResponse 对象。

现在我们了解了验证 webhook 所需的所有不同组件，让我们在下一个活动中构建一个。

## 活动 16.02：创建一个验证 webhook，检查 Pod 中是否存在标签

在这个活动中，我们将利用我们在本章和之前章节中所学到的知识，编写一个验证 webhook，验证请求的 Pod 中是否存在标签。

所需的步骤如下：

1.  创建一个名为`webhooks`的新命名空间。如果已经存在，请删除现有的命名空间，然后再次创建它。

1.  生成自签名的 CA 证书。

1.  生成 SSL 的私钥/公钥对，并使用 CA 证书进行签名。

1.  创建一个保存在上一步生成的私钥/公钥对的秘密。

注意

即使您拥有上一个活动的证书和密钥，我们建议您丢弃它们，重新开始，以避免任何冲突。

1.  编写 webhook 代码以检查是否存在具有键`teamName`的标签。如果不存在，则拒绝请求。

1.  将 webhook 代码打包为 Docker 容器。

1.  将 Docker 容器推送到您选择的公共存储库（quay.io 允许您创建一个免费的公共存储库）。

注意

如果您在构建自己的 webhook 时遇到任何困难，您可以使用此链接提供的代码作为参考：[`packt.live/2FbL7Jv`](https://packt.live/2FbL7Jv)。

如果您想避免构建和打包 webhook，我们提供了一个预构建的容器，以便您可以直接在部署中使用它。您可以从 Docker Hub 使用此镜像：`packtworkshops/the-kubernetes-workshop:webhook`。

使用此镜像可以跳过*步骤 5*至*7*。

1.  创建部署以部署 webhook 服务器。

1.  将 webhooks Deployment 公开为 Kubernetes 服务。

1.  创建 CA 证书的 Base64 编码版本。

1.  创建`ValidtingWebhookConfiguration`，以便 Kubernetes 可以拦截 API 调用并调用我们的 webhook。

1.  创建一个没有标签的简单 Pod，并验证它是否被拒绝。

1.  创建一个带有所需标签的简单 Pod，并验证它是否已创建。

1.  一旦创建了 Pod，请确保标签是 Pod 规范的一部分。

您可以通过尝试创建一个没有`teamName`标签的 Pod 来测试您的验证 webhook。它应该被拒绝，并显示以下消息：

![图 16.9：活动 16.02 的预期输出](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_16_09.jpg)

图 16.9：活动 16.02 的预期输出

注意

此活动的解决方案可以在以下地址找到：[`packt.live/304PEoD`](https://packt.live/304PEoD)。

## 控制 Webhook 对选定命名空间的影响

当您定义任何 webhook（变异或验证）时，您可以通过定义`namespaceSelector`参数来控制 webhook 将影响哪些命名空间。请注意，这仅适用于命名空间范围的对象。对于集群范围的对象，例如持久卷，此参数不会产生任何影响，并且将应用 webhook。

注意

并非所有准入控制器（变异或验证）都可以限制到一个命名空间。

就像许多 Kubernetes 对象一样，命名空间也可以有标签。我们将利用命名空间的这个属性，将 webhook 应用于特定的命名空间，正如您将在以下练习中看到的那样。

## 练习 16.03：使用命名空间选择器定义一个验证 Webhook

在这个练习中，我们将定义一个验证 webhook，强制执行一个自定义规则，应用于在`webhooks`命名空间中创建的 Pod。规则是 Pod 必须定义一个名为`teamName`的标签。由于该规则适用于在`webhooks-demo`命名空间中创建的 Pod，因此所有其他命名空间都可以创建没有定义标签的 Pod。

注意

在运行此练习之前，请确保您已完成*活动 16.02*，*创建一个检查 Pod 标签的验证 Webhook*，因为我们正在重用那里创建的对象。如果您在活动中遇到任何问题，可以在*附录*中查看解决方案。

1.  验证我们在*活动 16.02*中创建的验证 webhook 是否仍然存在：

```
kubectl get ValidatingWebHookConfiguration -n webhooks
```

您将看到以下响应：

```
NAME                        CREATED AT
pod-label-verify-webhook    201908-23T13:59:30Z
```

1.  现在，删除在*活动 16.02*中定义的现有验证 webhook，*创建一个检查 Pod 标签的验证 webhook*：

```
kubectl delete ValidatingWebHookConfiguration pod-label-verify-webhook -n webhooks
```

注意

`ValidatingWebHookConfiguration`是一个集群范围的对象，对于这个命令，指定`-n`标志是可选的。

您将会得到以下的响应：

![图 16.10：删除现有的验证 webhook](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_16_10.jpg)

图 16.10：删除现有的验证 webhook

1.  删除`webhooks`命名空间：

```
kubectl delete ns webhooks
```

您将会得到以下的响应：

```
namespace "webhooks" deleted
```

1.  创建`webhooks`命名空间：

```
kubectl create ns webhooks
```

您将会得到以下的响应：

```
namespace/webhooks created
```

现在我们应该有一个干净的板块来继续进行这个练习。

1.  创建一个新的 CA 捆绑和一个私钥/公钥对，用于这个 webhook。使用以下命令生成一个自签名证书：

```
openssl req -nodes -new -x509 -keyout controller_ca.key -out controller_ca.crt -subj "/CN=Mutating Admission Controller Webhook CA"
```

您将会得到类似以下的输出：

![图 16.11：生成一个自签名证书](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_16_11.jpg)

图 16.11：生成一个自签名证书

注意

即使您在之前的活动中已经创建了 CA 和密钥，您仍需要重新创建它们以使本练习正常工作。

1.  生成一个私钥/公钥对，并使用以下两个命令依次对其进行 CA 证书签名：

```
openssl genrsa -out tls.key 2048
openssl req -new -key tls.key -subj "/CN=webhook-server.webhooks.svc" \
    | openssl x509 -req -CA controller_ca.crt -Cakey controller_ca.key -Cacreateserial -out tls.crt
```

您将会得到类似以下响应的输出：

![图 16.12：用我们的证书签署私钥/公钥对](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_16_12.jpg)

图 16.12：用我们的证书签署私钥/公钥对

1.  创建一个保存私钥/公钥对的 secret：

```
kubectl -n webhooks create secret tls webhook-server-tls \
--cert "tls.crt" \
--key "tls.key"
```

您应该会得到以下的响应：

```
secret/webhook-server-tls created
```

1.  接下来，我们需要在`webhooks`命名空间部署 webhook。创建一个名为`validating-server.yaml`的文件，内容如下：

```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: webhook-server
  labels:
    app: webhook-server
spec:
  replicas: 1
  selector:
    matchLabels:
      app: webhook-server
  template:
    metadata:
      labels:
        app: webhook-server
    spec:
      containers:
      - name: server
        image: packtworkshops/the-kubernetes-workshop:webhook
        imagePullPolicy: Always
        ports:
        - containerPort: 8443
          name: webhook-api
        volumeMounts:
        - name: webhook-tls-certs
          mountPath: /etc/secrets/tls
          readOnly: true
      volumes:
      - name: webhook-tls-certs
        secret:
          secretName: webhook-server-tls
```

注意

您可以使用在*活动 16.02*中创建的相同的 webhook 镜像，*创建一个检查 Pod 标签的验证 webhook*。在这个参考 YAML 中，我们使用了我们在仓库中提供的镜像。

1.  通过使用上一步的定义部署 webhook 服务器：

```
kubectl create -f validating-server.yaml -n webhooks
```

您应该会看到以下的响应：

```
deployment.apps/webhook-server created
```

1.  您可能需要等一会儿，检查 webhook Pods 是否已经创建。不断检查 Pods 的状态：

```
kubectl get pods -n webhooks -w
```

您应该会看到以下的响应：

![图 16.13：检查我们的 webhook 是否在线](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_16_13.jpg)

图 16.13：检查我们的 webhook 是否在线

注意，`-w`标志会持续监视 Pods。当所有的 Pods 都准备就绪时，您可以结束监视。

1.  现在，我们需要通过 Kubernetes 服务公开部署的 webhook 服务器。创建一个名为`validating-serversvc.yaml`的文件，内容如下：

```
apiVersion: v1
kind: Service
metadata:
  labels:
    app: webhook-server
  name: webhook-server
  namespace: webhooks
spec:
  ports:
  - port: 443
    protocol: TCP
    targetPort: 8443
  selector:
    app: webhook-server
  sessionAffinity: None
  type: ClusterIP
```

请注意，webhook 服务必须在端口`443`上运行，因为这是 TLS 通信的标准端口。

1.  使用上一步的定义来使用以下命令创建服务：

```
kubectl create -f validating-serversvc.yaml -n webhooks
```

您将看到以下输出：

```
service/webhook-server created
```

1.  创建 CA 证书的 Base64 编码版本。依次使用以下命令：

```
openssl x509 -inform PEM -in controller_ca.crt > controller_ca.crt.pem
openssl base64 -in controller_ca.crt.pem -out controller_ca-base64.crt.pem
```

第一个命令是将证书转换为 PEM 格式。第二个命令是将 PEM 证书转换为 Base64。这些命令不会有任何响应。您可以使用以下命令检查文件：

```
cat controller_ca-base64.crt.pem
```

文件内容应该是这样的：

![图 16.14：Base64 编码的 CA 证书内容](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_16_14.jpg)

图 16.14：Base64 编码的 CA 证书内容

请注意，您生成的 TLS 证书不会完全与此处显示的内容相同。

1.  使用以下两个命令清除我们的 CA 证书中的空行，并将内容添加到一个新文件中：

```
cat controller_ca-base64.crt.pem | tr -d '\n' > onelinecert.pem
cat onelinecert.pem
```

第一个命令不会有任何响应，第二个命令会打印出`onlinecert.pem`的内容。您应该会看到以下响应：

![图 16.15：去除换行符的 Base64 编码 CA 证书](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_16_15.jpg)

图 16.15：去除换行符的 Base64 编码 CA 证书

现在我们有了去除空行的 Base64 编码证书。在下一步中，我们将复制此输出中的值，注意不要复制结尾的`$`（在 Zsh 的情况下将是`%`）。将此值粘贴到`validation-config-namespace-scoped.yaml`中的`CA_BASE64_PEM`（`caBundle`的占位符）的位置，该文件将在下一步中创建。

1.  创建一个名为`validation-config-namespace-scoped.yaml`的文件，使用以下`ValidatingWebHookConfiguration`规范来配置 Kubernetes API 服务器调用我们的 webhook：

```
apiVersion: admissionregistration.k8s.io/v1beta1
kind: ValidatingWebhookConfiguration
metadata:
  name: pod-label-verify-webhook
webhooks:
  - name: webhook-server.webhooks.svc
    namespaceSelector:
      matchExpressions:
      - key: applyValidation
        operator: In
        values: ["true","yes", "1"]

    clientConfig:
      service:
        name: webhook-server
        namespace: webhooks
        path: "/validate"
      caBundle: "CA_BASE64_PEM"    #Retain the quotes when you         copy the caBundle here. Please read the note below on         how to add specific values here.
    rules:
      - operations: [ "CREATE" ]
        apiGroups: [""]
        apiVersions: ["v1"]
        resources: ["pods"]
        scope: "Namespaced"
```

注意

`CA_BASE64_PEM`占位符将被替换为上一步中`onelinecert.pem`的内容。请注意不要复制任何换行符。

1.  根据上一步中定义的 webhook 创建 webhook。确保用之前步骤中创建的证书替换`caBundle`字段：

```
kubectl create -f validation-config-namespace-scoped.yaml
```

您将看到以下响应：

![图 16.16：创建 ValidatingWebhookConfiguration](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_16_16.jpg)

图 16.16：创建 ValidatingWebhookConfiguration

1.  按照以下方式创建一个名为`webhooks-demo`的新命名空间：

```
kubectl create namespace webhooks-demo
```

您应该看到以下响应：

```
namespace/webhooks-demo created
```

1.  将`applyValidation=true`标签应用到`webhooks`命名空间，如下所示：

```
kubectl label namespace webhooks applyValidation=true
```

您应该看到以下响应：

```
namespace/webhooks labeled
```

此标签将与*步骤 14*中定义的选择器匹配，并确保我们的验证标准（由 webhook 强制执行）适用于此命名空间。请注意，我们没有给`webhooks-demo`命名空间贴上标签，因此验证将*不*适用于此命名空间。

1.  现在定义一个没有`teamName`标签的 Pod。创建一个名为`target-validating-pod.yaml`的文件，内容如下：

```
apiVersion: v1
kind: Pod
metadata:
  name: validating-pod-example
spec:
  containers:
    - name: validating-pod-example-container
      image: k8s.gcr.io/busybox
      command: [ "/bin/sh", "-c", "while :; do echo '.'; sleep         5 ; done" ]
```

1.  根据上一步的定义，在`webhooks`命名空间中创建 Pod：

```
kubectl create -f target-validating-pod.yaml -n webhooks
```

Pod 的创建应该被拒绝，如下所示：

![图 16.17：由于缺少必需标签而被拒绝的 Pod](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_16_17.jpg)

图 16.17：由于缺少必需标签而被拒绝的 Pod

请记住，我们的 webhook 只检查 Pod 中的`teamName`标签。根据*步骤 14*中定义的命名空间选择器，Pod 创建将被拒绝。

1.  现在，尝试在`webhooks-demo`命名空间中创建相同的 Pod，看看情况是否不同：

```
kubectl create -f target-validating-pod.yaml -n webhooks-demo
```

您应该得到这样的响应：

```
pod/validating-pod-example created
```

我们成功在`webhooks-demo`命名空间中创建了 Pod，但在`webhooks`命名空间中无法创建。

1.  让我们描述一下 Pod 以获取更多细节：

```
kubectl describe pod validating-pod-example -n webhooks-demo
```

您应该看到类似于这样的响应：

![图 16.18：检查我们的 Pod 的规范](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_16_18.jpg)

图 16.18：检查我们的 Pod 的规范

正如您所看到的，这个 Pod 没有任何标签，但我们仍然能够创建它。这是因为我们的验证 webhook 没有监视`webhooks-demo`命名空间。

在这个练习中，您已经学会了如何配置 webhook 以在命名空间级别进行更改。这对于测试功能并为可能拥有不同命名空间的不同团队提供不同功能可能很有用。

# 摘要

在本章中，我们了解到准入控制器提供了一种在创建、更新和删除操作期间强制执行对象的变异和验证的方式。这是扩展 Kubernetes 平台以符合您组织标准的简单方法。它们可以用于将最佳实践和策略应用到 Kubernetes 集群上。

接下来，我们学习了什么是变异和验证 webhook，如何配置它们，以及如何在 Kubernetes 平台上部署它们。Webhook 提供了一种简单的方式来扩展 Kubernetes，并帮助您适应特定企业的需求。

在之前的一系列章节中，从*第十一章*，*构建您自己的 HA 集群*，到*第十五章*，*Kubernetes 中的监控和自动扩展*，您学会了如何在 AWS 上设置高可用性集群，并运行无状态和有状态的应用程序。在接下来的几章中，您将学习许多高级技能，这些技能将帮助您不仅仅是运行应用程序，还能够利用 Kubernetes 提供的许多强大的管理功能，并保持集群的健康。

具体来说，在下一章中，您将了解 Kubernetes 调度器。这是一个决定 Pod 将被调度到哪些节点的组件。您还将学习如何配置调度器以符合您的需求，以及如何控制 Pod 在节点上的放置。


# 第十七章： Kubernetes 中的高级调度

概述

本章重点介绍调度，即 Kubernetes 选择运行 Pod 的节点的过程。在本章中，我们将更仔细地研究这个过程和 Kubernetes 调度器，这是负责这个过程的默认 Kubernetes 组件。

通过本章的学习，您将能够使用不同的方式来控制 Kubernetes 调度器的行为，以满足应用程序的要求。本章将使您能够选择适当的 Pod 调度方法，根据业务需求控制您想要在哪些节点上运行 Pod。您将了解在 Kubernetes 集群上控制 Pod 调度的不同方式。

# 介绍

我们已经看到，我们将我们的应用程序打包为容器，并将它们部署为 Kubernetes 中的 Pod，这是部署的最小单位。借助 Kubernetes 提供的先进调度功能，我们可以优化这些 Pod 的部署，以满足我们的硬件基础设施的需求，并充分利用可用资源。

Kubernetes 集群通常有多个节点（或机器或主机），可以在其中执行 Pod。假设您正在管理一些机器，并且已被指定在这些机器上执行应用程序。为了决定哪台机器最适合给定的应用程序，您会怎么做？在本次研讨会中，每当您想在 Kubernetes 集群上运行 Pod 时，您是否提到过 Pod 应该在哪个节点上运行？

没错 - 我们不需要; Kubernetes 配备了一个智能组件，可以找到最适合运行您的 Pod 的节点。这个组件就是**Kubernetes 调度器**。在本章中，我们将更深入地了解 Kubernetes 调度器的工作原理，以及如何调整它以更好地控制我们的集群，以满足不同的需求。

# Kubernetes 调度器

如介绍中所述，典型的集群有多个节点。当您创建一个 Pod 时，Kubernetes 必须选择一个节点并将 Pod 分配给它。这个过程被称为**Pod 调度**。

负责决定将 Pod 分配给哪个节点以执行的 Kubernetes 组件称为调度器。Kubernetes 配备了一个默认调度器，适用于大多数用例。例如，默认的 Kubernetes 调度器在集群中均匀分配负载。

现在，考虑这样一个场景：两个不同的 Pod 预计经常需要相互通信。作为系统架构师，您可能希望它们位于同一节点上，以减少延迟并释放一些内部网络带宽。调度器不知道不同类型的 Pod 之间的关系，但 Kubernetes 提供了方法来告知调度器这种关系，并影响调度行为，以便这两个不同的 Pod 可以托管在同一节点上。但首先，让我们更仔细地看一下 Pod 的**调度过程**。

# Pod 调度过程

调度器的工作分为三个步骤：**过滤**、**评分**和**分配**。让我们来看看在执行每个步骤时会发生什么。下图描述了该过程的概述：

![图 17.1：Kubernetes Scheduler 选择合适节点的概述](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_17_01.jpg)

图 17.1：Kubernetes Scheduler 选择合适节点的概述

## 过滤

过滤是指**Kubernetes Scheduler**运行一系列检查或过滤器，以查看哪些节点不适合运行目标 Pod 的过程。过滤器的一个例子是查看节点是否有足够的 CPU 和内存来托管 Pod，或者 Pod 请求的存储卷是否可以挂载在主机上。如果集群中没有适合满足 Pod 要求的节点，那么 Pod 被视为不可调度，并且不会在集群上执行。

## 评分

一旦**Kubernetes Scheduler**有了可行节点的列表，第二步是对节点进行评分，并找到最适合托管目标 Pod 的节点。节点会经过几个优先函数，并分配一个优先级分数。每个函数都会分配一个介于 0 和 10 之间的分数，其中 0 是最低的，10 是最高的。

为了理解优先级函数，让我们以`SelectorSpreadPriority`为例。这个优先级函数使用标签选择器来找到相关的 Pod。比如说，一堆 Pod 是由同一个部署创建的。正如 SpreadPriority 这个名字所暗示的，这个函数试图将 Pod 分布在不同的节点上，这样在节点故障的情况下，我们仍然会在其他节点上运行副本。在这个优先级函数下，Kubernetes Scheduler 选择使用与请求的 Pod 相同的标签选择器运行最少的节点。这些节点将被分配最高的分数，反之亦然。

另一个优先级函数的示例是`LeastRequestedPriority`。这试图在具有最多资源可用的节点上分配工作负载。调度程序获取已分配给现有 Pod 的内存和 CPU 最少的节点。这些节点被分配最高的分数。换句话说，这个优先级函数将为更多的空闲资源分配更高的分数。

注意

在本章的有限范围内，有太多的优先级函数需要涵盖。完整的优先级函数列表可以在以下链接找到：[`kubernetes.io/docs/concepts/scheduling/kube-scheduler/#scoring`](https://kubernetes.io/docs/concepts/scheduling/kube-scheduler/#scoring)。

## 分配

最后，调度程序通知 API 服务器已基于最高分数选择的节点。如果有多个具有相同分数的节点，调度程序会选择一个随机节点，并有效地应用决胜局。

默认的 Kubernetes Scheduler 作为一个 Pod 在`kube-system`命名空间中运行。您可以通过列出`kube-system`命名空间中的所有 Pod 来查看它的运行情况：

```
kubectl get pods -n kube-system
```

您应该看到以下 Pod 列表：

![图 17.2：在 kube-system 命名空间中列出 Pod](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_17_02.jpg)

图 17.2：在 kube-system 命名空间中列出 Pod

在我们的 Minikube 环境中，Kubernetes Scheduler Pod 的名称为`kube-scheduler-minikube`，正如您在此截图中所看到的。

## Pod 调度时间表

让我们深入了解**Pod 调度**过程的时间线。当您请求创建一个 Pod 时，不同的 Kubernetes 组件会被调用来将 Pod 分配给正确的节点。从请求 Pod 到分配节点，涉及三个步骤。以下图表概述了这个过程，我们将在图表之后详细阐述和分解这个过程：

**步骤 2**：**Kubernetes 调度器**通过 API 服务器不断监视 Kubernetes 数据存储。一旦有 Pod 创建请求可用（或 Pod 处于挂起状态），调度器会尝试调度它。重要的是要注意，调度器不负责运行 Pod。它只是计算最适合托管 Pod 的节点，并通知 Kubernetes API 服务器，然后将这些信息存储在 etcd 中。在这一步中，Pod 被分配到最佳节点，并且关联关系被存储在 etcd 中。

管理 Kubernetes 调度器

图 17.3：Pod 调度过程的时间线

**步骤 1**：当提出创建和运行 Pod 的请求时，例如通过 kubectl 命令或 Kubernetes 部署，API 服务器会响应此请求。它会更新 Kubernetes 内部数据库（etcd），并将一个待执行的 Pod 条目添加到其中。请注意，在这个阶段，不能保证 Pod 将被调度。

污点和容忍

**步骤 3**：Kubernetes 代理（kubelet）通过 API 服务器不断监视 Kubernetes 数据存储。一旦一个新的 Pod 被分配到一个节点，它会尝试在节点上执行 Pod。当 Pod 成功启动并运行时，通过 API 服务器将其标记为在 etcd 中运行，此时过程完成。

现在我们对调度过程有了一定的了解，让我们看看如何调整它以满足我们的需求。

# ](image/B14870_17_03.jpg)

Kubernetes 提供了许多参数和对象，通过它们我们可以管理**Kubernetes 调度器**的行为。我们将研究以下管理调度过程的方式：

+   ![图 17.3：Pod 调度过程的时间线

+   Pod 亲和性和反亲和性

+   节点亲和性和反亲和性

+   Pod 优先级和抢占

## 节点亲和性和反亲和性

使用节点亲和规则，Kubernetes 集群管理员可以控制 Pod 在特定节点集上的放置。节点亲和性或反亲和性允许您根据节点的标签来限制 Pod 可以运行的节点。

想象一下，您是银行共享 Kubernetes 集群的管理员。多个团队在同一集群上运行其应用程序。您的组织安全组已经确定了可以运行数据敏感应用程序的节点，并希望您确保没有其他应用程序在这些节点上运行。节点亲和性或反亲和性规则为满足此要求提供了解决方案，只将特定的 Pod 关联到一组节点。

节点亲和规则由两个组件定义。首先，您为一组节点分配一个标签。第二部分是配置 Pod，使它们只与具有特定标签的节点相关联。另一种思考方式是，Pod 定义了它应该放置在哪里，调度程序将此定义中的标签与节点标签进行匹配。

有两种类型的节点亲和性/反亲和性规则：

+   必需规则是硬性规则。如果不满足这些规则，Pod 将无法在节点上调度。它在 Pod 规范的`requiredDuringSchedulingIgnoredDuringExecution`部分中定义。请参阅*练习 17.01*，*使用节点亲和性运行 Pod*，作为此规则的示例。

+   首选规则是软规则。调度程序尽量在可能的情况下执行首选规则，但如果规则无法执行，它会忽略这些规则，也就是说，如果严格遵循这些规则，Pod 将无法被调度。首选规则在 Pod 规范的`preferredDuringSchedulingIgnoredDuringExecution`部分中定义。

首选规则与每个标准相关联的权重。调度程序将根据这些权重创建一个分数，以在正确的节点上调度 Pod。权重字段的值范围从 1 到 100。调度程序计算所有合适节点的优先级分数，以找到最佳节点。请注意，分数可能会受到其他优先级函数的影响，例如`LeastRequestedPriority`。

如果您定义的权重太低（与其他权重相比），则整体分数将受到其他优先级函数的最大影响，我们的首选规则可能对调度过程产生很少影响。如果定义了多个规则，则可以更改对您最重要的规则的权重。

亲和规则是在 Pod 规范中定义的。基于我们期望/不期望的节点的标签，我们将在 Pod 规范中提供选择标准的第一部分。它包括一组标签，以及可选的标签值。

标准的另一部分是提供我们想要匹配标签的方式。我们将这些匹配标准定义为亲和性定义中的**运算符**。此运算符可以具有以下值：

+   `In`运算符指示调度程序在匹配标签和指定值之一的节点上调度 Pod。

+   `NotIn`运算符指示调度程序不要在不匹配标签和任何指定值的节点上调度 Pod。这是一个否定运算符，表示反亲和性配置。

+   `Exists`运算符指示调度程序在匹配标签的节点上调度 Pod。在这种情况下，标签的值并不重要。因此，即使指定的标签存在且标签的值不匹配，此运算符也是满足的。

+   `DoesNotExist`运算符指示调度程序不要在不匹配标签的节点上调度 Pod。在这种情况下，标签的值并不重要。这是一个否定运算符，表示反亲和性配置。

请注意，亲和性和反亲和性规则是基于节点上的标签定义的。如果节点上的标签发生更改，可能会导致节点亲和性规则不再适用。在这种情况下，正在运行的 Pod 将继续在节点上运行。如果重新启动 Pod，或者 Pod 死亡并创建了一个新的 Pod，Kubernetes 将视其为新的 Pod。在这种情况下，如果节点标签已被修改，调度程序可能不会将 Pod 放在同一节点上。当您修改节点标签时，这是您需要注意的事项。让我们在以下练习中为一个 Pod 实现这些规则。

## 练习 17.01：运行具有节点亲和性的 Pod

在这个练习中，我们将配置一个 Pod，以便在我们的 Minikube 环境中可用的节点上进行调度。我们还将看到，如果标签不匹配，Pod 将处于`Pending`状态。想象一下这种状态，在这种状态下，调度程序无法找到合适的节点分配给 Pod：

1.  使用以下命令创建一个名为`schedulerdemo`的新命名空间：

```
kubectl create ns schedulerdemo
```

您应该看到以下响应：

```
namespace/schedulerdemo created
```

1.  现在我们需要创建一个具有节点亲和性定义的 Pod。创建一个名为`pod-with-node-affinity.yaml`的文件，其中包含以下规范：

```
apiVersion: v1
kind: Pod
metadata:
  name: pod-with-node-affinity
spec:
  affinity:
nodeAffinity: 
requiredDuringSchedulingIgnoredDuringExecution: 
       nodeSelectorTerms:
       - matchExpressions:
- key: data-center 
operator: In 
           values:
- sydney 
  containers:
    - name: pod-with-node-affinity-container
      image: k8s.gcr.io/busybox
      command: [ "/bin/sh", "-c", "while :; do echo '.'; sleep         5 ; done" ]
```

请注意，在 Pod 规范中，我们已经添加了新的`affinity`部分。这个规则被配置为`requiredDuringSchedulingIgnoredDuringExecution`。这意味着如果没有具有匹配标签的节点，这个 Pod 将不会被调度。还要注意，根据`In`运算符，这里提到的表达式将与节点标签匹配。在这个例子中，匹配的节点将具有标签`data-center=sydney`。

1.  尝试创建这个 Pod，看看它是否被调度和执行：

```
kubectl create -f pod-with-node-affinity.yaml -n schedulerdemo
```

你应该看到以下响应：

```
pod/pod-with-node-affinity created
```

请注意，这里看到的响应并不一定意味着 Pod 已成功在节点上执行。让我们在下一步中检查一下。

1.  使用这个命令检查 Pod 的状态：

```
kubectl get pods -n schedulerdemo
```

你会看到以下响应：

```
NAME                     READY    STATUS    RESTARTS   AGE
pod-with-node-affinity   0/1      Pending   0          10s   
```

从这个输出中，你可以看到 Pod 处于`Pending`状态，没有被执行。

1.  检查`events`以查看为什么 Pod 没有被执行：

```
kubectl get events -n schedulerdemo
```

你会看到以下响应：

![图 17.4：获取事件列表](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_17_04.jpg)

图 17.4：获取事件列表

你可以看到 Kubernetes 说没有节点与此 Pod 的选择器匹配。

1.  在继续之前，让我们删除 Pod：

```
kubectl delete pod pod-with-node-affinity -n schedulerdemo
```

你应该看到以下响应：

```
pod "pod-with-node-affinity" deleted
```

1.  现在，让我们看看我们集群中有哪些节点可用：

```
kubectl get nodes
```

你会看到以下响应：

```
NAME        STATUS    ROLES    AGE    VERSION
minikube    Ready     master   105d   v1.14.3
```

由于我们使用的是 Minikube，只有一个名为`minikube`的节点可用。

1.  检查`minikube`节点的标签。使用如下所示的`describe`命令：

```
kubectl describe node minikube
```

你应该看到以下响应：

![图 17.5：描述 minikube 节点](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_17_05.jpg)

图 17.5：描述 minikube 节点

正如你所看到的，我们想要的标签`data-center=sydney`并不存在。

1.  现在，让我们使用这个命令将期望的标签应用到我们的节点上：

```
kubectl label node minikube data-center=sydney
```

你会看到以下响应，表明节点已被标记：

```
node/minikube labeled
```

1.  使用`describe`命令验证标签是否应用到节点上：

```
kubectl describe node minikube
```

你应该看到以下响应：

![图 17.6：检查 minikube 节点上的标签](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_17_06.jpg)

图 17.6：检查 minikube 节点上的标签

正如你在这张图片中看到的，我们的标签现在已经被应用。

1.  现在再次尝试运行 Pod，看看它是否可以被执行：

```
kubectl create -f pod-with-node-affinity.yaml -n schedulerdemo
```

你应该看到以下响应：

```
pod/pod-with-node-affinity created
```

1.  现在，让我们检查一下 Pod 是否成功运行：

```
kubectl get pods -n schedulerdemo
```

你应该看到以下响应：

```
NAME                     READY    STATUS     RESTARTS   AGE
pod-with-node-affinity   1/1      Running    0          5m22s
```

因此，我们的 Pod 成功运行。

1.  让我们来看看 `events` 中如何显示 Pod 调度：

```
kubectl get events -n schedulerdemo
```

你将得到以下响应：

![图 17.7：查看调度事件](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_17_07.jpg)

图 17.7：查看调度事件

正如你在前面的输出中看到的，Pod 已成功调度。

1.  现在，让我们进行一些清理工作，以避免与进一步的练习和活动发生冲突。使用以下命令删除 Pod：

```
kubectl delete pod pod-with-node-affinity -n schedulerdemo
```

你应该看到以下响应：

```
pod "pod-with-node-affinity" deleted
```

1.  使用以下命令从节点中删除标签：

```
kubectl label node minikube data-center-
```

请注意，从 Pod 中删除标签的语法在标签名称后有一个额外的连字符（`–`）。你应该看到以下响应：

```
node/minikube labeled
```

在这个练习中，我们已经看到了节点亲和力是如何工作的，通过给节点贴标签，然后在贴有标签的节点上调度 Pod。我们还看到了 Kubernetes 事件如何用于查看 Pod 调度的状态。

在这个练习中我们使用的 `data-center=sydney` 标签也暗示了一个有趣的用例。我们可以使用节点亲和性和反亲和性规则来定位不仅特定的 Pod，还有特定的服务器机架或数据中心。我们只需为特定服务器机架、数据中心、可用区等的所有节点分配特定的标签。然后，我们可以简单地挑选所需的目标来为我们的 Pod。

# Pod 亲和性和反亲和性

Pod 亲和力和 Pod 反亲和力允许你的 Pod 在被调度到节点之前检查在该节点上运行的其他 Pod。请注意，在这种情况下，其他 Pod 并不意味着相同 Pod 的新副本，而是与不同工作负载相关的 Pod。

Pod 亲和力允许你控制 Pod 有资格被调度到哪个节点，这取决于已经在该节点上运行的其他 Pod 的标签。其想法是满足在同一位置放置两种不同类型的容器的需求，或者将它们分开。

假设您的应用程序有两个组件：前端部分（例如 GUI）和后端（例如 API）。假设您希望将它们运行在同一主机上，因为如果前端和后端 Pod 在同一节点上托管，它们之间的通信将更快。在多节点集群（而不是 Minikube）上，默认情况下，调度程序将在不同的节点上调度这样的 Pod。Pod 亲和提供了一种控制 Pod 相对于彼此的调度的方式，以便我们可以确保应用程序的最佳性能。

定义 Pod 亲和需要两个组件。第一个组件定义了调度程序如何将目标 Pod（在我们之前的示例中，前端 Pod）与已经运行的 Pod（后端 Pod）相关联。这是通过 Pod 上的标签完成的。在 Pod 亲和规则中，我们提到了应该用于与新 Pod 相关联的其他 Pod 的哪些标签。标签选择器具有与节点亲和和反亲和部分中描述的类似操作符，用于匹配 Pod 的标签。

第二个组件描述了您希望在哪里运行目标 Pod。就像我们在前面的练习中看到的那样，我们可以使用 Pod 亲和规则将 Pod 调度到与其他 Pod 相同的节点（在我们的示例中，我们假设后端 Pod 是已经在运行的 otherPod），与其他 Pod 相同机架上的任何节点，与其他 Pod 相同数据中心的任何节点等等。该组件定义了 Pod 可以分配的节点集。为了实现这一点，我们对节点组进行标记，并在 Pod 规范中将此标签定义为`topologyKey`。例如，如果我们将主机名作为`topologyKey`的值，Pod 将被放置在同一节点上。

如果我们使用机架名称对节点进行标记，并将机架名称定义为`topologyKey`，那么候选 Pod 将被调度到具有相同机架名称标签的节点之一。

与前一节中定义的节点亲和规则类似，硬亲和规则和软亲和规则也存在。硬规则使用`requiredDuringSchedulingIgnoredDuringExecution`进行定义，而软规则使用`preferredDuringSchedulingIgnoredDuringExecution`进行定义。Pod 亲和配置中可能存在多种硬和软规则的组合。

## 练习 17.02：使用 Pod 亲和运行 Pod

在这个练习中，我们将看到 Pod 亲和性如何帮助调度器查看不同 Pod 之间的关系，并将它们分配到合适的节点上。我们将使用`preferred`选项放置 Pod。在这个练习的后面部分，我们将使用`required`选项配置 Pod 反亲和性，并看到直到满足所有标准为止，该 Pod 都不会被调度。我们将使用前面提到的前端和后端 Pod 的相同示例：

1.  我们需要首先创建并运行后端 Pod。创建一个名为`pod-with-pod-affinity-first.yaml`的文件，内容如下：

```
apiVersion: v1
kind: Pod
metadata:
  name: pod-with-pod-affinity
  labels:
     application-name: banking-app
spec:
  containers:
    - name: pod-with-node-pod-container
      image: k8s.gcr.io/busybox
      command: [ "/bin/sh", "-c", "while :; do echo 'this is         backend pod'; sleep 5 ; done" ]
```

这个 Pod 是一个简单的 Pod，只是循环打印一条消息。请注意，我们为 Pod 分配了一个标签，以便它与前端 Pod 相关联。

1.  让我们创建上一步中定义的 Pod：

```
kubectl create -f pod-with-pod-affinity-first.yaml -n schedulerdemo
```

您应该看到以下响应：

```
pod/pod-with-pod-affinity created
```

1.  现在，让我们看看 Pod 是否已成功创建：

```
kubectl get pods -n schedulerdemo
```

您应该看到这样的响应：

```
NAME                     READY    STATUS    RESTARTS   AGE
pod-with-pod-affinity    1/1      Running   0          22s
```

1.  现在，让我们检查`minikube`节点上的标签：

```
kubectl describe node minikube
```

您应该看到以下响应：

![图 17.8：描述 minikube 节点](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_17_08.jpg)

图 17.8：描述 minikube 节点

由于我们希望在同一台主机上运行这两个 Pod，我们可以使用节点的`kubernetes.io/hostname`标签。

1.  现在，让我们定义第二个 Pod。创建一个名为`pod-with-pod-affinity-second.yaml`的文件，内容如下：

```
apiVersion: v1
kind: Pod
metadata:
  name: pod-with-pod-affinity-fe
  labels:
     application-name: banking-app
spec:
  affinity:
   podAffinity: 
     preferredDuringSchedulingIgnoredDuringExecution: 
     - weight: 100
       podAffinityTerm:
         labelSelector:
           matchExpressions:
           - key: application-name
             operator: In 
             values:
             - banking-app
         topologyKey: kubernetes.io/hostname
  containers:
    - name: pod-with-node-pod-container-fe
      image: k8s.gcr.io/busybox
      command: [ "/bin/sh", "-c", "while :; do echo 'this is         frontend pod'; sleep 5 ; done" ]
```

将此 Pod 视为前端应用程序。请注意，我们在`podAffinity`部分定义了`preferredDuringSchedulingIgnoredDuringExecution`规则。我们还为 Pod 和节点定义了`labels`和`topologyKey`。

1.  让我们创建上一步中定义的 Pod：

```
kubectl create -f pod-with-pod-affinity-second.yaml -n schedulerdemo
```

您应该看到以下响应：

```
pod/pod-with-pod-affinity-fe created
```

1.  使用`get`命令验证 Pod 的状态：

```
kubectl get pods -n schedulerdemo
```

您应该看到以下响应：

```
NAME                      READY    STATUS    RESTARTS   AGE
pod-with-pod-affinity     1/1      Running   0          7m33s
pod-with-pod-affinity-fe  1/1      Running   0          21s
```

如您所见，`pod-with-pod-affinity-fe` Pod 正在运行。这与普通的 Pod 放置没有太大不同。这是因为在 Minikube 环境中只有一个节点，并且我们使用了`preferredDuringSchedulingIgnoredDuringExecution`来定义 Pod 亲和性，这是匹配标准的软变体。

这个练习的下一步将讨论使用`requiredDuringSchedulingIgnoredDuringExecution`或匹配标准的硬变体的反亲和性，并且您将看到该 Pod 不会达到`Running`状态。

1.  首先，让我们删除`pod-with-pod-affinity-fe` Pod：

```
kubectl delete pod pod-with-pod-affinity-fe -n schedulerdemo
```

您应该看到以下响应：

```
pod "pod-with-pod-affinity-fe" deleted
```

1.  通过列出所有的 Pod 来确认 Pod 已被删除：

```
kubectl get pods -n schedulerdemo
```

您应该看到以下响应：

```
NAME                     READY    STATUS    RESTARTS   AGE
pod-with-pod-affinity    1/1      Running   0          10m
```

1.  现在创建另一个 Pod 定义，内容如下，并将其保存为`pod-with-pod-anti-affinity-second.yaml`：

```
apiVersion: v1
kind: Pod
metadata:
  name: pod-with-pod-anti-affinity-fe
  labels:
     application-name: backing-app
spec:
  affinity:
   podAntiAffinity: 
     requiredDuringSchedulingIgnoredDuringExecution: 
     - labelSelector:
         matchExpressions:
         - key: application-name
           operator: In 
           values:
           - banking-app
       topologyKey: kubernetes.io/hostname   
  containers:
    - name: pod-with-node-pod-anti-container-fe
      image: k8s.gcr.io/busybox
      command: [ "/bin/sh", "-c", "while :; do echo 'this is         frontend pod'; sleep 5 ; done" ]
```

正如您所看到的，配置是针对`podAntiAffinity`，它使用`requiredDuringSchedulingIgnoredDuringExecution`选项，这是 Pod 亲和性规则的硬变体。在这里，调度程序将不会调度任何 Pod，如果条件不满足。我们使用`In`运算符，以便我们的 Pod 不会在与配置的`labelSelector`组件中定义的任何 Pod 相同的主机上运行。

1.  尝试使用上述规范创建 Pod：

```
kubectl create -f pod-with-pod-anti-affinity-second.yaml -n schedulerdemo
```

您应该看到以下响应：

```
pod/pod-with-pod-anti-affinity-fe created
```

1.  现在，检查此 Pod 的状态：

```
kubectl get pods -n schedulerdemo
```

您应该看到以下响应：

```
NAME                           READY  STATUS    RESTARTS   AGE
pod-with-pod-affinity          1/1    Running   0          14m
pod-with-pod-anti-affinity-fe  1/1    Pending   0          3s
```

从这个输出中，您可以看到 Pod 处于`Pending`状态。

1.  您可以通过检查事件来验证 Pod 反亲和性导致 Pod 无法调度：

```
kubectl get events -n schedulerdemo
```

您应该看到以下响应：

![图 17.9：检查调度失败的事件](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_17_09.jpg)

图 17.9：检查调度失败的事件

在这个练习中，我们已经看到 Pod 亲和性如何帮助将两个不同的 Pod 放置在同一个节点上。我们还看到了 Pod 反亲和性选项如何帮助我们在不同的主机集上调度 Pod。

# Pod 优先级

Kubernetes 允许您为 Pod 关联一个优先级。如果存在资源约束，如果请求调度一个具有较高优先级的新 Pod，则 Kubernetes 调度程序可能会驱逐优先级较低的 Pod，以便为新的高优先级 Pod 腾出空间。

考虑一个例子，您是一个集群管理员，您在集群中运行关键和非关键的工作负载。一个例子是银行的 Kubernetes 集群。在这种情况下，您可能会有一个支付服务以及银行的网站。您可能会决定处理付款比运行网站更重要。通过配置 Pod 优先级，您可以防止低优先级的工作负载影响集群中的关键工作负载，特别是在集群开始达到其资源容量的情况下。将低优先级的 Pod 驱逐以安排更关键的 Pod 的技术可能比添加额外的节点更快，并且可以帮助您更好地管理集群上的流量波动。

将 Pod 与优先级关联的方式是定义一个名为`PriorityClass`的对象。该对象包含优先级，定义为 1 到 10 亿之间的数字。数字越高，优先级越高。一旦我们定义了我们的优先级类，我们通过将`PriorityClass`与 Pod 关联来为 Pod 分配优先级。默认情况下，如果 Pod 没有与其关联的优先级类，则 Pod 将被分配默认的优先级类（如果可用），或者将被分配优先级值为 0。

您可以像获取其他对象一样获取优先级类的列表：

```
kubectl get priorityclasses
```

您应该看到以下响应：

```
NAME                     VALUE         GLOBAL-DEFAULT   AGE
system-cluster-critical  2000000000    false            9d
system-node-critical     2000001000    false            9d
```

请注意，在 Minikube 中，环境中预定义了两个优先级类。让我们更多地了解`system-cluster-critical`类。发出以下命令以获取有关它的详细信息：

```
kubectl get pc system-cluster-critical -o yaml
```

您应该看到以下响应：

![图 17.10：描述 system-cluster-critical PriorityClass](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_17_10.jpg)

图 17.10：描述 system-cluster-critical PriorityClass

这里的输出提到这个类是为绝对关键的集群 Pod 保留的。etcd 就是这样的一个 Pod。让我们看看这个优先级类是否与它关联。

发出以下命令以获取有关在 Minikube 中运行的 etcd Pod 的详细信息：

```
kubectl get pod etcd-minikube -n kube-system -o yaml
```

您应该看到以下响应：

![图 17.11：获取有关 etcd-minikube Pod 的信息](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_17_11.jpg)

图 17.11：获取有关 etcd-minikube Pod 的信息

您可以从此输出中看到 Pod 已与`system-cluster-critical`优先级关联。

在接下来的练习中，我们将添加一个默认的优先级类和一个更高的优先级类，以更好地理解 Kubernetes 调度程序的行为。

重要的是要理解 Pod 优先级与其他规则（如 Pod 亲和性）协同工作。如果调度程序确定无法安排高优先级的 Pod，即使低优先级的 Pod 被驱逐，它也不会驱逐低优先级的 Pod。

同样，如果高优先级和低优先级的 Pod 正在等待调度，并且调度程序确定由于亲和性或反亲和性规则而无法安排高优先级的 Pod，则调度程序将安排适当的低优先级的 Pod。

## 练习 17.03：Pod 优先级和抢占

在这个练习中，我们将定义两个优先级类：默认（低优先级）和高优先级。然后，我们将创建 10 个具有默认优先级的 Pod，并为每个 Pod 分配一些 CPU 和内存。之后，我们将检查从我们的本地集群中使用了多少容量。然后，我们将创建 10 个具有高优先级的 Pod，并为它们分配资源。我们将看到具有默认优先级的 Pod 将被终止，并且更高优先级的 Pod 将被调度到集群上。然后，我们将把高优先级 Pod 的数量从 10 减少到 5，然后看到一些低优先级的 Pod 再次被调度。这是因为减少高优先级 Pod 的数量应该释放一些资源：

1.  首先，让我们为默认优先级类创建定义。使用以下内容创建一个名为`priority-class-default.yaml`的文件：

```
apiVersion: scheduling.k8s.io/v1
kind: PriorityClass
metadata:
  name: default-priority
value: 1
globalDefault: true
description: "Default Priority class."
```

请注意，我们通过将`globalDefault`的值设置为`true`来将此优先级类标记为默认。此外，优先级数字`1`非常低。

1.  使用以下命令创建此优先级类：

```
kubectl create -f priority-class-default.yaml
```

您应该看到以下响应：

```
priorityclass.scheduling.k8s.io/default-priority
```

请注意，由于此对象不是命名空间级对象，因此我们没有提及命名空间。优先级类是 Kubernetes 中的集群范围对象。

1.  让我们检查一下我们的优先级类是否已经创建：

```
kubectl get priorityclasses
```

您应该看到以下列表：

```
NAME                     VALUE         GLOBAL-DEFAULT   AGE
default-priority         1             true             5m46s
system-cluster-critical  2000000000    false            105d
system-node-critical     2000001000    false            105d
```

在此输出中，您可以看到我们刚刚创建的优先级类的名称为`default-priority`，并且正如您在`GLOBAL-DEFAULT`列中所看到的那样，它是全局默认的。现在创建另一个优先级更高的优先级类。

1.  使用以下内容创建一个名为`priority-class-highest.yaml`的文件：

```
apiVersion: scheduling.k8s.io/v1
kind: PriorityClass
metadata:
  name: highest-priority
value: 100000
globalDefault: false
description: "This priority class should be used for pods with   the highest of priority."
```

请注意此对象中`value`字段的非常高的值。

1.  使用上一步的定义使用以下命令创建一个 Pod 优先级类：

```
kubectl create -f priority-class-highest.yaml
```

您应该看到以下响应：

```
priorityclass.scheduling.k8s.io/highest-priority created
```

1.  现在让我们创建一个具有`10`个 Pod 和默认优先级的部署的定义。使用以下内容创建一个名为`pod-with-default-priority.yaml`的文件来定义我们的部署：

```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: pod-default-priority-deployment
spec:
  replicas: 10
  selector:
    matchLabels:
      app: priority-test

  template:
    metadata:
      labels:
        app: priority-test
    spec:
      containers:
      - name: pod-default-priority-deployment-container
        image: k8s.gcr.io/busybox
        command: [ "/bin/sh", "-c", "while :; do echo 'this is           backend pod'; sleep 5 ; done" ]
      priorityClassName: default-priority
```

1.  让我们创建我们在上一步中定义的部署：

```
kubectl create -f pod-with-default-priority.yaml -n schedulerdemo
```

您应该看到这个响应：

```
deployment.apps/pod-default-priority-deployment created
```

1.  现在，通过使用以下命令将每个 Pod 分配的内存和 CPU 增加到 128 MiB 和 CPU 的 1/10：

```
kubectl set resources deployment/pod-default-priority-deployment --limits=cpu=100m,memory=128Mi -n schedulerdemo
```

您应该看到以下响应：

```
deployment.extensions/pod-default-priority-deployment resource requirements updated
```

注意

您可能需要根据计算机上可用的资源调整此资源分配。您可以从 1/10 的 CPU 开始，并按照*步骤 10*中提到的方式验证资源。

1.  使用以下命令验证 Pod 是否正在运行：

```
kubectl get pods -n schedulerdemo
```

您应该会看到以下 Pod 列表：

![图 17.12：获取 Pod 列表](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_17_12.jpg)

图 17.12：获取 Pod 列表

1.  检查我们集群中的资源使用情况。请注意，我们只有一个节点，因此我们可以通过发出`describe`命令轻松地看到这些值：

```
kubectl describe node minikube
```

以下截图已经被截断以便更好地呈现。在您的输出中找到`分配的资源`部分：

![图 17.13：检查 minikube 节点上的资源利用率](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_17_13.jpg)

图 17.13：检查 minikube 节点上的资源利用率

请注意，`minikube`主机的 CPU 使用率为 77%，内存使用率为 64%。请注意，资源利用率取决于您计算机的硬件和分配给 Minikube 的资源。如果您的 CPU 太强大，或者您有大量的内存（甚至如果您的 CPU 较慢，内存较少），您可能会看到与我们在这里看到的资源利用率值大不相同。请根据*步骤 8*中提到的方式调整 CPU 和内存资源，以便我们获得与我们在这里看到的类似的资源利用率。这将使您能够看到与我们在本练习的后续步骤中演示的类似结果。

1.  现在让我们安排具有高优先级的 Pod。使用 Kubernetes 部署对象创建 10 个 Pod。为此，请创建一个名为`pod-with-high-priority.yaml`的文件，其中包含以下内容：

```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: pod-highest-priority-deployment
spec:
  replicas: 10
  selector:
    matchLabels:
      app: priority-test

  template:
    metadata:
      labels:
        app: priority-test
    spec:
      containers:
      - name: pod-highest-priority-deployment-container
        image: k8s.gcr.io/busybox
        command: [ "/bin/sh", "-c", "while :; do echo 'this is           backend pod'; sleep 5 ; done" ]
      priorityClassName: highest-priority
```

请注意，在前面的规范中，`priorityClassName`已设置为`highest-priority`类。

1.  现在创建我们在上一步中创建的部署：

```
kubectl create -f pod-with-high-priority.yaml -n schedulerdemo
```

您应该会得到以下输出：

```
deployment.apps/pod-with-highest-priority-deployment created
```

1.  为这些 Pod 分配与具有默认优先级的 Pod 相似的 CPU 和内存量：

```
kubectl set resources deployment/pod-highest-priority-deployment --limits=cpu=100m,memory=128Mi -n schedulerdemo
```

您应该看到以下响应：

```
deployment.apps/pod-highest-priority-deployment resource requirements updated
```

1.  大约一分钟后，运行以下命令以查看正在运行的 Pod：

```
kubectl get pods -n schedulerdemo
```

您应该看到类似于这样的响应：

![图 17.14：获取 Pod 列表](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_17_14.jpg)

图 17.14：获取 Pod 列表

您可以看到我们大多数高优先级的 Pod 都处于`Running`状态，而低优先级的 Pod 已经移动到`Pending`状态。这告诉我们 Kubernetes 调度程序实际上已经终止了低优先级的 Pod，并且现在正在等待资源再次安排它们。

1.  尝试将高优先级的 Pod 数量从 10 个更改为 5 个，看看是否可以安排额外的低优先级 Pod。使用此命令更改副本的数量：

```
kubectl scale deployment/pod-highest-priority-deployment --replicas=5 -n schedulerdemo
```

您应该看到以下响应：

```
deployment.extensions/pod-highest-priority-deployment scaled
```

1.  使用以下命令验证高优先级的 Pod 是否从 10 个减少到 5 个：

```
kubectl get pods -n schedulerdemo
```

![图 17.15：获取 Pod 列表](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_17_15.jpg)

图 17.15：获取 Pod 列表

正如您在此截图中所看到的，一些更低优先级的 Pod 已经从`Pending`状态变为`Running`状态。因此，我们可以看到调度程序正在根据工作负载的优先级来充分利用可用资源。

在这个练习中，我们已经使用了 Pod 优先级规则，并看到了 Kubernetes 调度程序可能会选择终止具有较低优先级的 Pod，如果有对具有较高优先级的 Pod 的请求需要满足。

# 污点和忍受度

之前，我们已经看到 Pod 可以配置以控制它们在哪个节点上运行。现在我们将看到节点如何控制可以在其上运行的 Pod，使用污点和忍受度。

污点阻止了 Pod 的调度，除非该 Pod 具有与之匹配的忍受度。将污点视为节点的属性，而忍受度是 Pod 的属性。只有当 Pod 的忍受度与节点的污点匹配时，Pod 才会被安排在该节点上。节点上的污点告诉调度程序检查哪些 Pod 能容忍污点，并且只运行与节点的污点匹配的 Pod。

污点定义包含键、值和效果。键和值将与 Pod 规范中的 Pod 忍受度定义匹配，而效果指示调度程序一旦节点的污点与 Pod 的忍受度匹配应该执行什么操作。

以下图表提供了一个概述，说明了基于污点和忍受度控制调度的过程是如何工作的。请注意，具有忍受度的 Pod 也可以安排在没有污点的节点上。

![图 17.16：污点和忍受度如何影响调度的概述](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_17_16.jpg)

图 17.16：污点和忍受度如何影响调度的概述

当我们定义一个污点时，我们还需要指定污点的行为。这可以通过以下值来指定：

+   `NoSchedule`提供了拒绝在节点上调度新 Pod 的能力。在定义污点之前已经调度的现有 Pod 将继续在节点上运行。

+   `NoExecute`污点提供了抵抗没有与污点匹配的容忍的新 Pod 的能力。它进一步检查所有正在节点上运行的现有 Pod 是否匹配此污点，并删除不匹配的 Pod。

+   `PreferNoSchedule`指示调度器避免在不容忍节点上调度 Pod。这是一个软规则，调度器会尝试找到正确的节点，但如果找不到其他适合定义的污点和容忍规则的节点，它仍会在节点上调度 Pod。

为了对节点应用污点，我们可以使用`kubectl taint`命令，如下所示：

```
kubectl taint nodes <NODE_NAME> <TAINT>:<TAINT_TYPE>
```

可能有很多原因你希望某些 Pod（应用程序）不在特定节点上运行。一个例子可能是需要专门的硬件，比如用于机器学习应用的 GPU。另一个情况可能是 Pod 上的软件的许可限制要求它在特定节点上运行。例如，在你的集群中有 10 个工作节点，只有 2 个节点被允许运行特定软件。使用污点和容忍的组合，你可以帮助调度器在正确的节点上调度 Pod。

## 练习 17.04：污点和容忍

在这个练习中，我们将看到污点和容忍如何允许我们在所需的节点上调度 Pod。我们将定义一个污点，并尝试在节点上调度一个 Pod。然后展示`NoExecute`功能，如果节点上的污点发生变化，Pod 可以从节点中移除：

1.  使用以下命令获取节点列表：

```
kubectl get nodes
```

你应该看到以下节点列表：

```
NAME       STATUS    ROLES    AGE    VERSION
minikube   Ready     master   44h    v1.14.3
```

请记住，在我们的 Minikube 环境中，我们只有一个节点。

1.  使用以下命令为`minikube`节点创建一个污点：

```
kubectl taint nodes minikube app=banking:NoSchedule
```

你应该看到以下响应：

```
node/minikube tainted
```

1.  验证节点是否已正确被污点。你可以使用`describe`命令查看节点上应用了哪些污点：

```
kubectl describe node minikube
```

你应该看到以下响应：

![图 17.17：检查 minikube 节点上的污点](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_17_17.jpg)

图 17.17：检查 minikube 节点上的污点

1.  现在，我们需要根据污点定义创建一个具有容忍度的 Pod。创建一个名为`pod-toleration-noschedule.yaml`的文件，内容如下：

```
apiVersion: v1
kind: Pod
metadata:
  name: pod-with-node-toleration-noschedule
spec:
  tolerations:
  - key: "app"
    operator: "Equal"
    value: "banking"
    effect: "NoSchedule"
  containers:
    - name: pod-with-node-toleration-noschedule-container
      image: k8s.gcr.io/busybox
      command: [ "/bin/sh", "-c", "while :; do echo '.'; sleep         5 ; done" ]
```

请注意，容忍度值与*步骤 1*中定义的污点相同，即`app=banking`。`effect`属性控制容忍度行为的类型。在这里，我们将`effect`定义为`NoSchedule`。

1.  让我们根据前面的规范创建 Pod：

```
kubectl create -f pod-toleration-noschedule.yaml -n schedulerdemo
```

这应该得到以下响应：

```
pod/pod-with-node-toleration-noschedule created
```

1.  使用以下命令验证 Pod 是否正在运行：

```
kubectl get pods -n schedulerdemo
```

您应该看到以下响应：

![图 17.18：获取 Pod 列表](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_17_18.jpg)

图 17.18：获取 Pod 列表

1.  现在让我们定义一个不匹配节点污点的容忍度的不同 Pod。创建一个名为`pod-toleration-noschedule2.yaml`的文件，内容如下：

```
apiVersion: v1
kind: Pod
metadata:
  name: pod-with-node-toleration-noschedule2
spec:
  tolerations:
  - key: "app"
    operator: "Equal"
    value: "hr"
    effect: "NoSchedule"
  containers:
    - name: pod-with-node-toleration-noschedule-container2
      image: k8s.gcr.io/busybox
      command: [ "/bin/sh", "-c", "while :; do echo '.'; sleep         5 ; done" ]
```

请注意，这里我们将容忍度设置为`app=hr`。我们需要一个具有相同污点以匹配此容忍度的 Pod。由于我们已经用`app=banking`污点了我们的节点，这个 Pod 不应该被调度程序调度。让我们在以下步骤中尝试一下。

1.  使用上一步的定义创建 Pod：

```
kubectl create -f pod-toleration-noschedule2.yaml -n schedulerdemo
```

这应该得到以下响应：

```
pod/pod-with-node-toleration-noschedule2 created
```

1.  使用以下命令检查 Pod 的状态：

```
kubectl get pods -n schedulerdemo
```

您应该看到以下响应：

![图 17.19：获取 Pod 列表](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_17_19.jpg)

图 17.19：获取 Pod 列表

您可以看到 Pod 处于`Pending`状态，而不是`Running`状态。

1.  在本练习的剩余部分中，我们将看到`NoExecute`效果如何指示调度程序甚至在将 Pod 调度到节点后将其删除。在此之前，我们需要进行一些清理。使用以下命令删除两个 Pod：

```
kubectl delete pod pod-with-node-toleration-noschedule pod-with-node-toleration-noschedule2 -n schedulerdemo
```

您应该看到以下响应：

```
pod "pod-with-node-toleration-noschedule" deleted
pod "pod-with-node-toleration-noschedule2" deleted
```

1.  使用以下命令从节点中删除污点：

```
kubectl taint nodes minikube app:NoSchedule-
```

请注意命令末尾的连字符（`-`），它告诉 Kubernetes 删除此标签。您应该看到以下响应：

```
node/minikube untainted
```

我们的节点处于未定义污点的状态。现在，我们想先以`app=banking`的容忍度运行一个 Pod 并分配该 Pod。一旦 Pod 处于`Running`状态，我们将从节点中删除污点并查看 Pod 是否已被删除。

1.  现在，再次使用`NoExecute`类型对节点进行污染：

```
kubectl taint nodes minikube app=banking:NoExecute
```

您应该看到以下响应：

```
node/minikube tainted
```

1.  现在，我们需要定义一个具有匹配容忍度的 Pod。创建一个名为`pod-toleration-noexecute.yaml`的文件，内容如下：

```
apiVersion: v1
kind: Pod
metadata:
  name: pod-with-node-toleration-noexecute
spec:
  tolerations:
  - key: "app"
    operator: "Equal"
    value: "banking"
    effect: "NoExecute"
  containers:
    - name: pod-with-node-toleration-noexecute-container
      image: k8s.gcr.io/busybox
      command: [ "/bin/sh", "-c", "while :; do echo '.'; sleep         5 ; done" ]
```

请注意，`tolerations`部分将标签定义为`app=banking`，效果定义为`NoExecute`。

1.  使用以下命令创建我们在上一步中定义的 Pod：

```
kubectl create -f pod-toleration-noexecute.yaml -n schedulerdemo
```

您应该看到以下响应：

```
pod/pod-with-node-toleration-noexecute created
```

1.  使用以下命令验证 Pod 是否处于`Running`状态：

```
kubectl get pods -n schedulerdemo
```

您应该看到以下响应：

![图 17.20：获取 Pod 列表](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_17_20.jpg)

图 17.20：获取 Pod 列表

1.  现在使用以下命令从节点中删除污点：

```
kubectl taint nodes minikube app:NoExecute-
```

请注意此命令末尾的连字符（`-`），它告诉 Kubernetes 删除污点。您将看到以下响应：

```
node/minikube untainted
```

如前所述，具有容忍度的 Pod 可以附加到没有污点的节点。删除污点后，Pod 仍将被执行。请注意，我们尚未删除 Pod，它仍在运行。

1.  现在，如果我们向节点添加一个带有`NoExecute`的新污点，Pod 应该会从中删除。要查看此操作，请添加一个与 Pod 容忍度不同的新污点：

```
kubectl taint nodes minikube app=hr:NoExecute
```

如您所见，我们已将`app=hr`污点添加到 Pod 中。您应该看到以下响应：

```
node/minikube tainted
```

1.  现在，让我们检查一下 Pod 的状态：

```
kubectl get pods -n schedulerdemo
```

您将看到以下响应：

![图 17.21：检查我们的 Pod 的状态](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_17_21.jpg)

图 17.21：检查我们的 Pod 的状态

Pod 将被删除或进入`Terminating`（标记为删除）状态。几秒钟后，Kubernetes 将删除 Pod。

在这个练习中，您已经看到我们如何在节点上配置污点，以便它们只接受特定的 Pod。您还配置了污点以影响正在运行的 Pod。

# 使用自定义 Kubernetes 调度程序

构建自己的功能齐全的调度程序超出了本研讨会的范围。但是，重要的是要理解，Kubernetes 平台允许您编写自己的调度程序，如果您的用例需要，尽管不建议使用自定义调度程序，除非您有非常专业的用例。

自定义调度程序作为普通 Pod 运行。您可以在运行应用程序的 Pod 的定义中指定使用自定义调度程序。您可以在 Pod 规范中添加一个`schedulerName`字段，其中包含自定义调度程序的名称，如此示例定义所示：

```
apiVersion: v1
kind: Pod
metadata:
  name: pod-with-custom-scheduler
spec:
  containers:
    - name: mutating-pod-example-container
      image: k8s.gcr.io/busybox
      command: [ "/bin/sh", "-c", "while :; do echo '.'; sleep 5 ;         done" ]
  schedulerName: "custom-scheduler"
```

为使此配置工作，假定集群中有一个名为`custom-scheduler`的自定义调度程序。

## 活动 17.01：配置 Kubernetes 调度程序以安排 Pod

假设您是 Kubernetes 集群的管理员，并且您面临以下情景：

1.  有一个 API Pod 提供当前的货币转换率。

1.  有一个 GUI Pod 在网站上显示转换率。

1.  有一个 Pod 为股票交易所提供实时货币转换率的服务。

您被要求确保 API 和 GUI Pod 在同一节点上运行。您还被要求在流量激增时给予实时货币转换器 Pod 更高的优先级。在此活动中，您将控制 Kubernetes 调度程序的行为以完成此活动。

此活动中的每个 Pod 应分配 0.1 CPU 和 100 MiB 内存。请注意，我们已经将 Pod 命名为 API、GUI 和实时，以便操作更简单。此活动中的 Pod 预计只会在控制台上打印表达式。您可以为它们全部使用 `k8s.gcr.io/busybox` 镜像。

注意

在开始此活动之前，请确保节点没有从之前的练习中被污染。要了解如何去除污点，请参阅本章的“练习 17.01”中的“步骤 15”，“在节点亲和性下运行 Pod”。

以下是此活动的一些指南：

1.  创建一个名为`scheduleractivity`的命名空间。

1.  为 API Pod 创建 Pod 优先级。

1.  部署并确保 API 和 GUI Pod 使用 Pod 亲和性在同一节点上。GUI Pod 应定义与 API Pod 在同一节点上的亲和性。

1.  将 API 和 GUI Pod 的副本扩展到各自的两个。

1.  为实时货币转换器 Pod 创建一个 Pod 优先级。确保之前定义的 API Pod 优先级低于实时 Pod，但大于 0。

1.  部署并运行一个实时货币转换器 Pod，副本数为 1。

1.  确保所有 Pod 都处于“运行”状态。

1.  现在，将实时货币转换器 Pod 的副本数量从 1 增加到 10。

1.  查看实时货币转换器 Pod 是否正在启动，GUI Pod 是否正在被驱逐。如果没有，请继续以 5 的倍数增加实时 Pod。

1.  根据您的资源和 Pod 的数量，调度程序可能会开始驱逐 API Pod。

1.  将实时 Pod 的副本数量从 10 减少到 1，并确保 API 和 GUI Pod 被重新调度到集群上。

完成活动后，预计 API 和 GUI Pod 每个将处于“运行”状态，以及一个实时 Pod，如下截图所示：

![图 17.22：活动 17.01 的预期输出](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_17_22.jpg)

图 17.22：活动 17.01 的预期输出

请注意，您的输出将根据系统资源而变化，因此您可能看不到与此截图完全相同的内容。

注意

此活动的解决方案可以在以下地址找到：[`packt.live/304PEoD`](https://packt.live/304PEoD)。

# 总结

Kubernetes 调度器是一个强大的软件，它抽象了在集群上为 Pod 选择合适节点的工作。调度器会监视未调度的 Pod，并尝试为它们找到合适的节点。一旦找到一个适合的节点，它会通过 API 服务器更新 etcd，表示该 Pod 已绑定到该节点。

随着 Kubernetes 的每一个发布，调度器都得到了成熟。调度器的默认行为对各种工作负载已经足够，尽管您也看到了许多定制调度器与 Pod 关联资源的方式。您已经看到了节点亲和性如何帮助您在所需的节点上调度 Pod。Pod 亲和性可以帮助您相对于另一个 Pod 调度一个 Pod，这对于多个模块被放置在一起的应用程序是一个很好的工具。污点和容忍也可以帮助您将特定的工作负载分配给特定的节点。您还看到了 Pod 优先级如何帮助您根据集群中可用的总资源调度工作负载。

在下一章中，我们将升级一个 Kubernetes 集群，实现零停机。如果您在集群中使用本章展示的任何技术配置了自定义调度，您可能需要相应地计划升级。由于升级将逐个关闭一个工作节点，可能会导致一些 Pod 由于您的配置而变得不可调度，这可能不是一个可接受的解决方案。
