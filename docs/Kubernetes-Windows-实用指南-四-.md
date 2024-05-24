# Kubernetes Windows 实用指南（四）

> 原文：[`zh.annas-archive.org/md5/D85F9AD23476328708B2964790249673`](https://zh.annas-archive.org/md5/D85F9AD23476328708B2964790249673)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四部分：使用 Kubernetes 编排 Windows 容器

在本节中，我们将使用 Kubernetes 来创建简单和复杂的应用程序架构，使用容器。我们将学习如何部署、扩展和监控这些应用程序，利用平台的强大功能。

本节包括以下章节：

+   第九章，*部署您的第一个应用程序*

+   第十章，*部署 Microsoft SQL Server 2019 和 ASP.NET MVC 应用程序*

+   第十一章，*配置应用程序以使用 Kubernetes 功能*

+   第十二章，*使用 Kubernetes 进行开发工作流*

+   第十三章，*保护 Kubernetes 集群和应用程序*

+   第十四章，*使用 Prometheus 监控 Kubernetes 应用程序*

+   第十五章，*灾难恢复*

+   第十六章，*运行 Kubernetes 的生产考虑*


# 第九章：部署您的第一个应用程序

在前几章中，我们介绍了 Kubernetes 的关键操作原则和 Windows/Linux 混合集群的部署策略。现在是时候更专注于部署和使用 Kubernetes 应用程序了。为了演示 Kubernetes 应用程序的基本操作，我们将使用在第八章中创建的 AKS Engine 混合 Kubernetes 集群，*部署混合 Azure Kubernetes 服务引擎集群*。您也可以使用本地混合集群，但您应该期望功能有限；例如，LoadBalancer 类型的服务将不可用。

本章涵盖以下主题：

+   命令式部署应用程序

+   使用 Kubernetes 清单文件

+   在 Windows 节点上调度 Pods

+   访问您的应用程序

+   扩展应用程序

# 技术要求

本章，您将需要以下内容：

+   已安装 Windows 10 Pro、企业版或教育版（1903 版本或更高版本，64 位）

+   Azure 帐户

+   使用 AKS Engine 部署的 Windows/Linux Kubernetes 集群

要跟着做，您需要自己的 Azure 帐户来为 Kubernetes 集群创建 Azure 资源。如果您之前还没有为前几章创建帐户，您可以在这里阅读更多关于如何获得个人使用的有限免费帐户：[`azure.microsoft.com/en-us/free/`](https://azure.microsoft.com/en-us/free/)。

使用 AKS Engine 部署 Kubernetes 集群已在第八章中介绍过，*部署混合 Azure Kubernetes 服务引擎集群*。

您可以从官方 GitHub 存储库下载本章的最新代码示例：[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/tree/master/Chapter09`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/tree/master/Chapter09)。

# 命令式部署应用程序

在 Kubernetes 世界中，管理应用程序时可以选择两种方法：命令式管理和声明式管理。命令式方法包括执行命令式 kubectl 命令，例如`kubectl run`或`kubectl expose`，以及命令式对象配置管理，其中您使用命令，如`kubectl create`或`kubectl replace`。简而言之，您通过执行临时命令来管理集群，这些命令修改 Kubernetes 对象并导致集群的期望状态发生变化 - 有时，您甚至可能不知道命令式命令之后期望状态的确切变化。相比之下，在声明式方法中，您修改对象配置（清单文件），并使用`kubectl apply`命令在集群中创建或更新它们（或者，您可以使用 Kustomization 文件）。

使用声明性管理通常更接近 Kubernetes 的精神 - 整个架构都专注于保持期望的集群状态，并不断执行操作，将当前集群状态更改为期望的状态。一个经验法则是，在生产环境中，您应该始终使用声明性管理，无论是使用标准清单文件还是 Kustomization 文件。您可以轻松为对象配置提供源代码控制，并将其集成到持续集成/部署流水线中。命令式管理对于开发和概念验证场景非常有用 - 操作直接在活动集群上执行。

请记住，对于这种方法，您将无法轻松地了解先前配置的历史！

现在，让我们首先尝试使用命令式方法部署一个简单的 Web 应用程序。我们将执行以下操作：

1.  创建一个单独的裸 Pod 或 ReplicationController。

1.  使用 Service（LoadBalancer 类型）来公开它。

要命令式地创建一个 pod 或 ReplicationController，我们将使用`kubectl run`命令。此命令允许您使用生成器创建不同的容器管理对象。您可以在官方文档中找到生成器的完整列表：[`kubernetes.io/docs/reference/kubectl/conventions/#generators`](https://kubernetes.io/docs/reference/kubectl/conventions/#generators)——自 Kubernetes 1.12 以来，除了`run-pod/v1`之外的所有生成器都已被弃用。这样做的主要原因是`kubectl run`命令的相对复杂性，以及鼓励在高级场景中采用适当的声明性方法。

要部署基于`mcr.microsoft.com/dotnet/core/samples:aspnetapp` Docker 映像的示例应用程序，请执行以下步骤：

1.  打开 PowerShell 窗口，并确保您正在使用`kubeconfig`文件，该文件允许您连接到您的 AKS Engine 混合集群。

1.  确定集群中的节点上可用的 Windows Server 操作系统的版本。例如，对于 Windows Server 2019 Datacenter 节点，您需要使用具有基础层版本 1809 的容器映像。这意味着在我们的示例中，我们必须使用`mcr.microsoft.com/dotnet/core/samples:aspnetapp-nanoserver-1809` Docker 映像：

```
kubectl get nodes -o wide
```

1.  使用`run-pod/v1`生成器执行`kubectl run`命令以运行单个 pod，`windows-example`，用于具有节点选择器和操作系统类型以及`windows`的示例应用程序：

```
kubectl run `
 --generator=run-pod/v1 `
 --image=mcr.microsoft.com/dotnet/core/samples:aspnetapp-nanoserver-1809 `
 --overrides='{\"apiVersion\": \"v1\", \"spec\": {\"nodeSelector\": { \"beta.kubernetes.io/os\": \"windows\" }}}' `
 windows-example
```

1.  pod 将被调度到 Windows 节点之一，并且您可以使用以下命令监视 pod 创建的进度：

```
PS C:\src> kubectl get pods -w
NAME              READY   STATUS              RESTARTS   AGE
windows-example   0/1     ContainerCreating   0          7s
```

1.  当 pod 将其状态更改为`Running`时，您可以继续使用 LoadBalancer 服务暴露 pod：

```
kubectl expose pod windows-example `
 --name windows-example-service `
 --type LoadBalancer `
 --port 8080 `
 --target-port 80
```

1.  等待服务的`EXTERNAL-IP`可用：

```
PS C:\src> kubectl get service -w
NAME                      TYPE           CLUSTER-IP     EXTERNAL-IP      PORT(S)          AGE
kubernetes                ClusterIP      10.0.0.1       <none>           443/TCP          24h
windows-example-service   LoadBalancer   10.0.192.180   213.199.135.14   8080:30746/TCP   5m10s
```

1.  现在，您可以使用服务的外部 IP 和端口`8080`来访问在 pod 中运行的应用程序。例如，在 Web 浏览器中，导航到`http://213.199.135.14:8080/`。

或者，前面的步骤可以在一个`kubectl run`命令中完成，该命令将创建 pod 并立即使用 LoadBalancer 服务进行暴露：

```
kubectl run `
 --generator=run-pod/v1 `
 --image=mcr.microsoft.com/dotnet/core/samples:aspnetapp-nanoserver-1809 `
 --overrides='{\"apiVersion\": \"v1\", \"spec\": {\"nodeSelector\": { \"beta.kubernetes.io/os\": \"windows\" }}}' `
 --expose `
 --port 80 `
 --service-overrides='{ \"spec\": { \"type\": \"LoadBalancer\" }}' `
 windows-example
```

请注意，此命令使用端口`80`而不是`8080`来暴露服务。使用服务端口`80`和目标端口`8080`需要在`--service-overrides`标志中增加另一层复杂性。

为了完整起见，让我们在 Kubernetes ReplicationController 对象后面运行我们的`mcr.microsoft.com/dotnet/core/samples:aspnetapp-nanoserver-1809`容器。您可以在第四章中了解有关 ReplicationControllers、ReplicaSets 和 Deployments 的更多信息，*Kubernetes 概念和 Windows 支持*——通常情况下，在集群中运行裸 Pods 并不明智；您应该始终使用至少 ReplicaSets 或更好地使用 Deployments 来管理 Pods。在 Kubernetes 1.17 中，仍然可以使用`kubectl run`创建 ReplicationController——生成器已被弃用，但尚未删除。使用命令来声明式地创建 ReplicationController 需要使用不同的`--generator`标志，其值为`run/v1`：

```
kubectl run `
 --generator=run/v1  `
 --image=mcr.microsoft.com/dotnet/core/samples:aspnetapp-nanoserver-1809 `
 --overrides='{\"apiVersion\": \"v1\", \"spec\": {\"nodeSelector\": { \"beta.kubernetes.io/os\": \"windows\" }}}' `
 --expose `
 --port 80 `
 --service-overrides='{ \"spec\": { \"type\": \"LoadBalancer\" }}' `
 windows-example
```

即使这种方法快捷且不需要任何配置文件，你可以清楚地看到，除了简单操作之外，使用`kubectl run`变得复杂且容易出错。在大多数情况下，您将使用命令来执行以下操作：

+   在开发集群中快速创建 Pods

+   为了调试目的创建临时交互式 Pods

+   可预测地删除 Kubernetes 资源——在下一节中会详细介绍

现在让我们通过使用 Kubernetes 清单文件和声明式管理方法来执行类似的部署。

# 使用 Kubernetes 清单文件

Kubernetes 对象的声明式管理更接近于 Kubernetes 的精神——您专注于告诉 Kubernetes 您想要什么（描述所需状态），而不是直接告诉它要做什么。随着应用程序的增长和组件的增加，使用命令来管理集群变得不可能。最好使用命令来进行只读操作，例如`kubectl describe`、`kubectl get`和`kubectl logs`，并使用`kubectl apply`命令和 Kubernetes 对象配置文件（也称为清单文件）对集群的期望状态进行所有修改。

在使用清单文件时有一些推荐的做法：

+   最好使用 YAML 清单文件而不是 JSON 清单文件。 YAML 更容易管理，而且在 Kubernetes 社区中更常用。

+   将您的清单文件存储在 Git 等源代码控制中。在将任何配置更改应用到集群之前，先将更改推送到源代码控制中——这将使回滚和配置恢复变得更加容易。最终，您应该将此过程自动化为 CI/CD 流水线的一部分。

+   将多个清单文件组合成单个文件是推荐的，只要有意义。官方 Kubernetes 示例存储库提供了这种方法的很好演示：[`github.com/kubernetes/examples/blob/master/guestbook/all-in-one/guestbook-all-in-one.yaml`](https://github.com/kubernetes/examples/blob/master/guestbook/all-in-one/guestbook-all-in-one.yaml).

+   如果您的集群有多个清单文件，您可以使用 `kubectl apply` 递归地应用给定目录中的所有清单文件。

+   使用 `kubectl diff` 来了解将应用到当前集群配置的变化。

+   在删除 Kubernetes 对象时，请使用命令式的 `kubectl delete` 命令，因为它能给出可预测的结果。您可以在官方文档中了解更多关于资源声明式删除的信息，但在实践中，这是一种更具风险的方法：[`kubernetes.io/docs/tasks/manage-kubernetes-objects/declarative-config/#how-to-delete-objects`](https://kubernetes.io/docs/tasks/manage-kubernetes-objects/declarative-config/#how-to-delete-objects.).

+   尽可能使用标签来语义化地描述您的组件：[`kubernetes.io/docs/concepts/configuration/overview/#using-labels`](https://kubernetes.io/docs/concepts/configuration/overview/#using-labels.).

关于清单文件的更多最佳实践可以在官方文档中找到：[`kubernetes.io/docs/concepts/configuration/overview/`](https://kubernetes.io/docs/concepts/configuration/overview/).

现在，让我们尝试通过部署一个类似上一节中的应用程序来演示这种方法。这次，我们将使用 Deployment 和 service 对象，它们将在单独的清单文件中定义——在实际场景中，您可能会将这两个清单文件组合成一个文件，但出于演示目的，将它们分开是有意义的。按照以下步骤部署应用程序：

1.  打开 PowerShell 窗口。

1.  确保您的集群没有运行上一节中的资源——您可以使用 `kubectl get all` 命令来检查并使用 `kubectl delete` 命令来删除它们。

1.  为清单文件创建一个目录，例如`declarative-demo`：

```
md .\declarative-demo
cd .\declarative-demo
```

1.  创建包含部署定义的`windows-example-deployment.yaml`清单文件：

```
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: windows-example
  labels:
    app: sample
spec:
  replicas: 1
  selector:
    matchLabels:
      app: windows-example
  template:
    metadata:
      name: windows-example
      labels:
        app: windows-example
    spec:
      nodeSelector:
        "beta.kubernetes.io/os": windows
      containers:
      - name: windows-example
        image: mcr.microsoft.com/dotnet/core/samples:aspnetapp-nanoserver-1809
        ports:
          - containerPort: 80
```

1.  创建包含 LoadBalancer 服务定义的`windows-example-service.yaml`清单文件：

```
---
apiVersion: v1
kind: Service
metadata:
  name: windows-example
spec:
  type: LoadBalancer
  ports:
  - protocol: TCP
    port: 8080
    targetPort: 80
  selector:
    app: windows-example
```

1.  使用`kubectl apply`命令在当前目录中应用清单文件。请注意，如果您有多级目录层次结构，您可以使用`-R`标志进行递归处理：

```
PS C:\src\declarative-demo> kubectl apply -f .\
deployment.apps/windows-example created
service/windows-example created
```

1.  使用以下命令等待服务的外部 IP 可用：

```
PS C:\src\declarative-demo> kubectl get service -w
NAME              TYPE           CLUSTER-IP    EXTERNAL-IP   PORT(S)          AGE
kubernetes        ClusterIP      10.0.0.1      <none>        443/TCP          44h
windows-example   LoadBalancer   10.0.63.175   51.144.36.7   8080:30568/TCP   3m28s
```

1.  使用您的网络浏览器导航到外部 IP 和端口`8080`。

现在，让我们看看如何使用声明式方法对应用程序进行简单更改——我们想将 LoadBalancer 端口更改为`9090`：

1.  打开包含 LoadBalancer 服务定义的`windows-example-service.yaml`清单文件。

1.  将`spec.ports[0].port`值修改为`9090`。

1.  保存清单文件。

1.  （可选但建议）使用`kubectl diff`命令验证您的更改。请记住，您需要安装并在`$env:KUBECTL_EXTERNAL_DIFF`环境变量中定义适当的*diff*工具；您可以在第六章中了解更多信息，*与 Kubernetes 集群交互*：

```
kubectl diff -f .\
```

1.  再次应用清单文件：

```
PS C:\src\declarative-demo> kubectl apply -f .\
deployment.apps/windows-example unchanged
service/windows-example configured
```

1.  请注意，只有`service/windows-example`被检测为所需配置中的更改。

1.  现在，您可以在网络浏览器中导航到外部 IP 地址和端口`9090`以验证更改。

1.  如果您想删除当前目录中由清单文件创建的所有资源，可以使用以下命令：

```
kubectl delete -f .\
```

就是这样！正如您所看到的，声明式管理可能需要更多的样板配置，但最终，使用这种方法管理应用程序更加可预测和易于跟踪。

在管理在多个环境中运行的复杂应用程序时，考虑使用 Kustomization 文件（可与`kubectl apply`命令一起使用）或 Helm Charts。例如，使用 Kustomization 文件，您可以将配置文件组织在一个符合约定的目录结构中：[`kubectl.docs.kubernetes.io/pages/app_composition_and_deployment/structure_directories.html`](https://kubectl.docs.kubernetes.io/pages/app_composition_and_deployment/structure_directories.html)。

在下一节中，我们将简要介绍关于在 Windows 节点上调度 Pod 的推荐做法。

# 在 Windows 节点上调度 Pods

要在具有特定属性的节点上调度 Pods，Kubernetes 为您提供了一些可能的选项：

+   在 Pod 规范中使用`nodeName`。这是在给定节点上静态调度 Pods 的最简单形式，通常不建议使用。

+   在 Pod 规范中使用`nodeSelector`。这使您有可能仅在具有特定标签值的节点上调度您的 Pod。我们在上一节中已经使用了这种方法。

+   节点亲和性和反亲和性：这些概念扩展了`nodeSelector`方法，并提供了更丰富的语言来定义哪些节点是首选或避免为您的 Pod。您可以在官方文档中了解更多可能性：[`kubernetes.io/docs/concepts/configuration/assign-pod-node/#affinity-and-anti-affinity`](https://kubernetes.io/docs/concepts/configuration/assign-pod-node/#affinity-and-anti-affinity)。

+   节点污点和 Pod 容忍度：它们提供了与节点亲和性相反的功能-您将一个污点应用于给定节点（描述某种限制），Pod 必须具有特定的容忍度才能在被污染的节点上调度。

在混合 Windows/Linux 集群中调度 Pods 至少需要使用`nodeSelector`或一组带有`nodeSelector`的节点污点的组合。每个 Kubernetes 节点默认都带有一组标签，其中包括以下内容：

+   `kubernetes.io/arch`，描述节点的处理器架构，例如`amd64`或`arm`：这也被定义为`beta.kubernetes.io/arch`。

+   `kubernetes.io/os`，其值为`linux`或`windows`：这也被定义为`beta.kubernetes.io/os`。

您可以使用以下命令在 AKS Engine 集群中检查 Windows 节点（例如`7001k8s011`）的默认标签：

```
PS C:\src> kubectl describe node 7001k8s011
Name:               7001k8s011
Roles:              agent
Labels:             agentpool=windowspool2
 beta.kubernetes.io/arch=amd64
 beta.kubernetes.io/instance-type=Standard_D2_v3
 beta.kubernetes.io/os=windows
 failure-domain.beta.kubernetes.io/region=westeurope
 failure-domain.beta.kubernetes.io/zone=0
 kubernetes.azure.com/cluster=aks-engine-windows-resource-group
 kubernetes.azure.com/role=agent
 kubernetes.io/arch=amd64
 kubernetes.io/hostname=7001k8s011
 kubernetes.io/os=windows
 kubernetes.io/role=agent
 node-role.kubernetes.io/agent=
 storageprofile=managed
 storagetier=Standard_LRS
```

如果您的 Pod 规范中不包含`nodeSelector`，它可以在 Windows 和 Linux 节点上都可以调度-这是一个问题，因为 Windows 容器不会在 Linux 节点上启动，反之亦然。建议的做法是使用`nodeSelector`来可预测地调度您的 Pods，无论是 Windows 还是 Linux 容器。例如，在部署定义中，Pod 模板可能包含以下内容：

```
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: windows-example
spec:
...
  template:
...
    spec:
      nodeSelector:
        "beta.kubernetes.io/os": windows
...
```

或者，您可以在 Kubernetes 的最新版本中使用`"kubernetes.io/os": windows`选择器。对于 Linux 容器，您需要指定`"beta.kubernetes.io/os": linux`或`"kubernetes.io/os": linux`。

当您将 Windows 节点添加到现有的大型 Linux-only 集群中时，这种方法可能会导致问题，使用 Helm Charts 或 Kubernetes Operators - 这些工作负载可能没有默认指定 Linux 节点选择器。为了解决这个问题，您可以使用污点和容忍：使用特定的`NoSchedule`污点标记您的 Windows 节点，并为您的 Pod 使用匹配的容忍。我们将使用带有`os`键和值`Win1809`的污点来实现这个目的。

对于污点 Windows 节点，您有两种可能性：

+   在 kubelet 的注册级别上使用`--register-with-taints='os=Win1809:NoSchedule'`标志对节点进行污点。请注意，这种方法目前在 AKS Engine 中不可用，因为`--register-with-taints`不是用户可配置的 - 您可以在文档中阅读更多信息：[`github.com/Azure/aks-engine/blob/master/docs/topics/clusterdefinitions.md#kubeletconfig`](https://github.com/Azure/aks-engine/blob/master/docs/topics/clusterdefinitions.md#kubeletconfig)。

+   使用 kubectl 对节点进行污点。您可以使用以下命令添加一个污点：`kubectl taint nodes <nodeName> os=Win1809:NoSchedule`，并使用`kubectl taint nodes 7001k8s011 os:NoSchedule-`来删除它。

然后，您的部署定义将不得不为 Windows 指定适当的 Pod 节点选择器和污点容忍，以允许在 Windows 节点上调度：

```
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: windows-example
spec:
...
  template:
...
    spec:
      nodeSelector:
        "beta.kubernetes.io/os": windows
      tolerations:
      - key: "os"
        operator: "Equal"
        value: "Win1809"
        effect: "NoSchedule"
...
```

在这种方法中，对于 Linux 容器，您不需要指定任何节点选择器或污点容忍。但是，如果可能的话，建议使用节点选择器方法而不使用节点污点，特别是如果您正在构建一个新的集群。

在下一节中，我们将看看如何访问您的应用程序。

# 访问您的应用程序

要访问在 Pod 中运行的应用程序，根据您的情况，您有一些可能性。在调试和测试场景中，您可以通过以下简单的方式访问您的应用程序：

+   使用`kubectl exec`来创建一个临时的交互式 Pod。我们在之前的章节中使用了这种方法。

+   使用`kubectl proxy`来访问任何服务类型。这种方法仅适用于 HTTP(S)端点，因为它使用 Kubernetes API 服务器提供的代理功能。

+   使用`kubectl port-forward`。您可以使用这种方法来访问单个 Pod 或在部署或服务后面运行的 Pod。

如果您想要为生产环境的最终用户公开应用程序，您可以使用以下方法：

+   具有 LoadBalancer 或 NodePort 类型的服务对象：我们已经在上一节中演示了如何使用 LoadBalancer 服务。

+   使用 Ingress Controller 与 ClusterIP 类型的服务一起使用：这种方法减少了使用的云负载均衡器的数量（从而降低了运营成本），并在 Kubernetes 集群内执行负载均衡和路由。请注意，这种方法使用 L7 负载均衡，因此只能用于暴露 HTTP（S）端点。

您可以在《Kubernetes 网络》第五章中详细了解服务和 Ingress Controller。在本节的后面，我们将演示如何为演示应用程序使用 Ingress Controller。

您可以在官方文档中了解有关在集群中运行的应用程序的访问的更多信息：[`kubernetes.io/docs/tasks/administer-cluster/access-cluster-services/#accessing-services-running-on-the-cluster`](https://kubernetes.io/docs/tasks/administer-cluster/access-cluster-services/#accessing-services-running-on-the-cluster)。

让我们首先演示如何使用`kubectl proxy`和`kubectl port-forward`。执行以下步骤：

1.  打开一个 Powershell 窗口。

1.  确保之前部分中的演示应用程序已部署，并且在集群中部署了一个端口为`8080`的`windows-example`服务。

1.  运行`kubectl proxy`命令：

```
PS C:\src\declarative-demo> kubectl proxy
Starting to serve on 127.0.0.1:8001
```

1.  这将在本地主机的端口`8001`上暴露一个简单的代理服务器到远程 Kubernetes API 服务器。您可以自由地使用此端点使用 API，无需额外的身份验证。请注意，也可以使用原始 API 而不使用代理，但那样您就必须自己处理身份验证（[`kubernetes.io/docs/tasks/administer-cluster/access-cluster-api/`](https://kubernetes.io/docs/tasks/administer-cluster/access-cluster-api/)）。

1.  您的服务将在`http://<proxyEndpoint>/api/v1/namespaces/<namespaceName>/services/[https:]<serviceName>[:portName]/proxy`上可用。在我们的情况下，导航到`http://127.0.0.1:8001/api/v1/namespaces/default/services/windows-example/proxy/`。这种方法适用于任何服务类型，包括仅内部 ClusterIPs。

1.  终止`kubectl proxy`进程。

1.  现在，执行以下`kubectl port-forward`命令：

```
PS C:\src\declarative-demo> kubectl port-forward service/windows-example 5000:8080
Forwarding from 127.0.0.1:5000 -> 80
Forwarding from [::1]:5000 -> 80
```

1.  这将把来自您的本地主机`5000`端口的任何网络流量转发到`windows-example`服务的`8080`端口。例如，您可以在 Web 浏览器中导航到`http://127.0.0.1:5000/`。请注意，这种方法也适用于 HTTP(S)以外的不同协议。

1.  终止`kubectl port-forward`进程。

现在，让我们看看如何使用 Ingress Controller 来访问演示应用程序。使用 Ingress 是高度可定制的，有多个可用的 Ingress Controllers——我们将演示在 AKS Engine 混合集群上快速启动和运行`ingress-nginx`（[`www.nginx.com/products/nginx/kubernetes-ingress-controller`](https://www.nginx.com/products/nginx/kubernetes-ingress-controller)）。请注意，这种方法将 Ingress Controllers 的部署限制在 Linux 节点上——您将能够为运行在 Windows 节点上的服务创建 Ingress 对象，但所有的负载均衡将在 Linux 节点上执行。按照以下步骤：

1.  修改`windows-example-service.yaml`清单文件，使其具有`type: ClusterIP`，`port: 80`，并且没有`targetPort`：

```
apiVersion: v1
kind: Service
metadata:
  name: windows-example
spec:
  type: ClusterIP
  ports:
  - protocol: TCP
    port: 80
  selector:
    app: windows-example
```

1.  将您的修改应用到集群中：

```
kubectl apply -f .\
```

1.  应用官方的通用清单文件用于 ingress-nginx，它在 Linux 节点上创建一个具有一个副本的部署：

```
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/master/deploy/static/mandatory.yaml
```

1.  申请官方的云特定清单文件用于 ingress-nginx。这将创建一个 LoadBalancer 类型的服务，用于 Ingress Controller：

```
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/master/deploy/static/provider/cloud-generic.yaml
```

1.  等待 Ingress Controller 服务接收外部 IP 地址。外部 IP 地址`104.40.133.125`将用于所有配置在此 Ingress Controller 后运行的服务：

```
PS C:\src\declarative-demo> kubectl get service -n ingress-nginx -w
NAME            TYPE           CLUSTER-IP    EXTERNAL-IP      PORT(S)                      AGE
ingress-nginx   LoadBalancer   10.0.110.35   104.40.133.125   80:32090/TCP,443:32215/TCP   16m
```

1.  创建`windows-example-ingress.yaml`清单文件并定义 Ingress 对象。我们的应用程序的`windows-example`服务将在`<ingressLoadBalancerIp>/windows-example`路径下注册：

```
apiVersion: networking.k8s.io/v1beta1
kind: Ingress
metadata:
  name: windows-example-ingress
  annotations:
    kubernetes.io/ingress.class: "nginx"
    nginx.ingress.kubernetes.io/rewrite-target: /$2
    nginx.ingress.kubernetes.io/ssl-redirect: "false"
spec:
  rules:
  - http:
      paths:
      - path: /windows-example(/|$)(.*)
        backend:
          serviceName: windows-example
          servicePort: 80
```

1.  应用更改：

```
kubectl apply -f .\
```

1.  导航到`http://104.40.133.125/windows-example`来测试 Ingress 定义。

当然，您可以为不同的服务创建多个 Ingress 对象，具有复杂的规则。一个经验法则是，尽可能使用 Ingress Controller 来公开您的 HTTP(S)端点，并为其他协议使用专用的 LoadBalancer 服务。

现在，让我们看看如何扩展您的应用程序！

# 扩展应用程序

在生产场景中，您肯定需要扩展您的应用程序 - 这就是 Kubernetes 强大之处；您可以手动扩展您的应用程序，也可以使用自动缩放。让我们首先看看如何执行部署的手动扩展。您可以通过命令或声明性地执行。要使用 PowerShell 中的命令执行扩展操作，请执行以下步骤：

1.  执行 `kubectl scale` 命令，将 `windows-example` 部署扩展到三个副本：

```
PS C:\src\declarative-demo> kubectl scale deployment/windows-example --replicas=3
deployment.extensions/windows-example scaled
```

1.  现在观察 Pods 如何被添加到您的部署中：

```
PS C:\src\declarative-demo> kubectl get pods -w
NAME READY STATUS RESTARTS AGE
windows-example-5cb7456474-5ndrm 0/1 ContainerCreating 0 8s
windows-example-5cb7456474-v7k84 1/1 Running 0 23m
windows-example-5cb7456474-xqp86 1/1 Running 0 8s
```

您也可以以声明性的方式执行类似的操作，这通常是推荐的。让我们进一步将应用程序扩展到四个副本：

1.  编辑 `windows-example-deployment.yaml` 清单文件，并将 `replicas` 修改为 `4`。

1.  保存清单文件并应用更改：

```
PS C:\src\declarative-demo> kubectl apply -f .\
deployment.apps/windows-example configured
ingress.networking.k8s.io/windows-example-ingress unchanged
service/windows-example unchanged
```

1.  再次使用 `kubectl get pods -w` 命令观察应用程序如何扩展。

Kubernetes 的真正力量在于自动缩放。我们将在第十一章 *配置应用程序使用 Kubernetes 功能* 中更详细地介绍自动缩放，因此在本节中，我们只会简要概述如何使用命令来执行它：

1.  首先，您需要为部署中的 pod 模板配置 CPU 资源限制 - 将其设置为一个小值，例如 `100m`。如果没有 CPU 资源限制，自动缩放将无法正确应用扩展策略：

```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: windows-example
...
spec:
...
    spec:
...
      containers:
      - name: windows-example
...
        resources:
          limits:
            cpu: 100m
          requests:
            cpu: 100m
```

1.  应用修改：

```
kubectl apply -f .\
```

1.  执行以下 `kubectl autoscale` 命令：

```
kubectl autoscale deployment/windows-example --cpu-percent=15 --min=1 --max=5
```

1.  这将在集群中创建一个**水平 Pod 自动缩放器**（HPA）对象，采用默认算法，最少 1 个副本，最多 5 个副本，并基于目标 CPU 使用率的 15% 的限制进行配置。

1.  使用以下命令来检查 HPA 的状态：

```
kubectl describe hpa windows-example
```

1.  您可以尝试通过频繁刷新应用程序网页向您的 Pod 添加一些 CPU 负载。请注意，如果您使用 Ingress，您将命中 Ingress 控制器的缓存，因此在这种情况下 CPU 使用率可能不会增加。

1.  过一段时间，您会看到自动缩放开始并添加更多副本。当您减少负载时，部署将被缩减。您可以使用 `kubectl describe` 命令来检查时间线：

```
PS C:\src\declarative-demo> kubectl describe hpa windows-example
...
 Normal   SuccessfulRescale             11m                horizontal-pod-autoscaler  New size: 3; reason: cpu resource utilization (percentage of request) above target
 Normal   SuccessfulRescale             4m17s              horizontal-pod-autoscaler  New size: 1; reason: All metrics below target
```

1.  使用此命令删除 HPA 对象以关闭自动缩放：

```
kubectl delete hpa windows-example
```

对于托管的 AKS 实例，可以利用**节点级**自动缩放功能（[`docs.microsoft.com/en-us/azure/aks/cluster-autoscaler`](https://docs.microsoft.com/en-us/azure/aks/cluster-autoscaler)），为您的工作负载带来了另一个可伸缩性维度。此外，您可以考虑使用 Azure 容器实例（ACI）与 AKS 工作负载（[`docs.microsoft.com/en-us/azure/architecture/solution-ideas/articles/scale-using-aks-with-aci`](https://docs.microsoft.com/en-us/azure/architecture/solution-ideas/articles/scale-using-aks-with-aci)）。

恭喜！您已成功在 AKS Engine 混合 Kubernetes 集群上部署和自动缩放了您的第一个应用程序。

# 总结

本章简要介绍了如何在 AKS Engine 混合集群上部署和管理运行 Windows 容器应用程序。您学会了命令式和声明式集群配置管理的区别以及何时使用它们。我们已经使用了这两种方法来部署演示应用程序-现在您知道推荐的声明式方法比使用命令式命令更容易，更不容易出错。接下来，您将学习如何可预测地在 Windows 节点上安排 Pod，并如何处理将 Windows 容器工作负载添加到现有 Kubernetes 集群。最后，我们展示了如何访问在 Kubernetes 中运行的应用程序，供最终用户和开发人员使用，以及如何手动和自动扩展应用程序。

在下一章中，我们将利用所有这些新知识来将一个真正的.NET Framework 应用程序部署到我们的 Kubernetes 集群！

# 问题

1.  Kubernetes 对象的命令式和声明式管理有什么区别？

1.  何时推荐使用命令式命令？

1.  如何查看本地清单文件和当前集群状态之间的更改？

1.  在混合集群中安排 Pod 的推荐做法是什么？

1.  `kubectl proxy`和`kubectl port-forward`命令之间有什么区别？

1.  何时可以使用 Ingress Controller？

1.  如何手动扩展部署？

您可以在本书的*评估*中找到这些问题的答案。

# 进一步阅读

+   有关 Kubernetes 应用程序管理的更多信息，请参考以下 Packt 图书：

+   《完整的 Kubernetes 指南》（[`www.packtpub.com/virtualization-and-cloud/complete-kubernetes-guide`](https://www.packtpub.com/virtualization-and-cloud/complete-kubernetes-guide)）

+   使用 Kubernetes 入门-第三版（[`www.packtpub.com/virtualization-and-cloud/getting-started-kubernetes-third-edition`](https://www.packtpub.com/virtualization-and-cloud/getting-started-kubernetes-third-edition)）

+   *面向开发人员的 Kubernetes*（[`www.packtpub.com/virtualization-and-cloud/kubernetes-developers`](https://www.packtpub.com/virtualization-and-cloud/kubernetes-developers)）

+   目前，关于在 AKS Engine 上运行的混合 Windows/Linux 集群的大多数资源都可以在线获得。请查看 GitHub 上的官方文档以获取更多详细信息：

+   [`github.com/Azure/aks-engine/blob/master/docs/topics/windows.md`](https://github.com/Azure/aks-engine/blob/master/docs/topics/windows.md)

+   [`github.com/Azure/aks-engine/blob/master/docs/topics/windows-and-kubernetes.md`](https://github.com/Azure/aks-engine/blob/master/docs/topics/windows-and-kubernetes.md)

+   一般来说，许多关于 AKS（托管的 Kubernetes Azure 提供的内容，而不是 AKS Engine 本身）的主题都很有用，因为它们涉及如何将 Kubernetes 与 Azure 生态系统集成。您可以在以下 Packt 书籍中找到有关 AKS 本身的更多信息：

+   *使用 Kubernetes 进行 DevOps-第二版*（[`www.packtpub.com/virtualization-and-cloud/devops-kubernetes-second-edition`](https://www.packtpub.com/virtualization-and-cloud/devops-kubernetes-second-edition)）


# 第十章：部署 Microsoft SQL Server 2019 和 ASP.NET MVC 应用程序

之前的章节为您提供了一个部署和操作混合 Windows/Linux Kubernetes 集群的瑞士军刀，现在，您已经掌握了部署真实 Windows 容器应用程序到 Kubernetes 集群的所有基本知识。本章将重点演示如何处理使用 C# .NET Framework 4.8 和 ASP.NET MVC 5 编写的简单投票应用程序的容器化和部署，其中 Microsoft SQL Server 2019 用于持久层。技术栈的选择可能看起来是传统的（为什么不使用.NET Core？！），但这是有意为之——如果您正在考虑在 Kubernetes 中使用 Windows 容器，那么您很可能需要经典的.NET Framework 运行时，因为您还没有准备好迁移到.NET Core。

迁移现有应用程序到 Kubernetes 的主题是广泛的，本书不会对其进行全面覆盖。有许多关于这一过程的最佳实践文档，但我们将专注于基本方法，主要是为了演示部署而不是专注于.NET Framework 应用程序的实现和迁移。本章的目标是展示以下内容：

+   如何快速将 Windows .NET Framework 应用程序容器化

+   如何注入环境配置，如 SQL 连接字符串

+   Windows 容器日志的推荐方法

+   如何远程调试应用程序

更准确地说，在本章中，我们将涵盖以下主题：

+   创建并发布 ASP.NET MVC 应用程序到 Docker Hub

+   准备**Azure Kubernetes 服务引擎**（**AKS 引擎**）

+   部署故障转移 Microsoft SQL Server 2019

+   部署 ASP.NET MVC 应用程序

+   访问应用程序

+   扩展应用程序

+   调试应用程序

# 技术要求

对于本章，您将需要以下内容：

+   安装 Windows 10 专业版、企业版或教育版（1903 版或更高版本，64 位）。

+   Microsoft Visual Studio 2019 社区版（或其他任何版本），如果您想编辑应用程序的源代码并对其进行调试。**Visual Studio Code**（**VS Code**）对经典.NET Framework 的支持有限。

+   Azure 账户。

+   使用 AKS 引擎部署的 Windows/Linux Kubernetes 集群。

要跟着做，您需要自己的 Azure 账户，以便为 Kubernetes 集群创建 Azure 资源。如果您之前还没有为前几章创建账户，您可以在这里了解如何获得用于个人使用的有限免费账户：[`azure.microsoft.com/en-us/free/`](https://azure.microsoft.com/en-us/free/)。

使用 AKS Engine 部署 Kubernetes 集群已在第八章中进行了介绍，*部署混合 Azure Kubernetes 服务引擎集群*。

您可以从官方 GitHub 存储库下载本书章节的最新代码示例，网址为：[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/tree/master/Chapter10`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/tree/master/Chapter10)。

# 创建并发布一个 ASP.NET MVC 应用程序到 Docker Hub

为了演示部署一个真实的 Windows 容器应用程序，我们将为一个投票应用程序创建一个 Docker 镜像，这是一个用于创建调查的小型 C# .NET Framework 4.8 Web 应用程序。该应用程序使用经典的 ASP.NET MVC 5 堆栈实现，因为它最适合演示如何处理 Windows 应用程序的容器化。传统的.NET Framework 应用程序，特别是企业级应用程序，严重依赖于仅在 Windows 上可用的功能，比如**Windows Communication Foundation**（**WCF**）。在许多情况下，您可能很幸运地轻松迁移到.NET Core，并使用 Linux 容器来托管您的应用程序，但对于.NET Framework 堆栈的某些部分，甚至在.NET 5 中也可能永远不会发生。

关于我们的投票应用程序，有一些假设，如下：

+   本文中没有任何对 Kubernetes 或 Windows 容器的依赖。该应用程序不知道自己是由容器编排系统托管的。

+   **Entity Framework 6.3**（**EF 6.3**）([`docs.microsoft.com/en-us/ef/ef6/`](https://docs.microsoft.com/en-us/ef/ef6/))采用了基于代码的方式作为**对象关系映射**（**ORM**）。

+   Microsoft SQL Server 用于投票数据存储-这是您在 ASP.NET MVC 应用程序中看到的常见堆栈。对于本地开发，我们使用 Microsoft SQL（MSSQL）Server Express LocalDB（[`docs.microsoft.com/en-us/sql/database-engine/configure-windows/sql-server-express-localdb?view=sql-server-ver15`](https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/sql-server-express-localdb?view=sql-server-ver15)），而对于 Kubernetes 部署，我们将使用托管在 Linux 容器中的 MSSQL Server 2019（[`docs.microsoft.com/en-us/sql/linux/quickstart-install-connect-docker?view=sql-server-ver15&pivots=cs1-bash`](https://docs.microsoft.com/en-us/sql/linux/quickstart-install-connect-docker?view=sql-server-ver15&pivots=cs1-bash)）。

+   Serilog（[`serilog.net/`](https://serilog.net/)）已被选择为日志框架。

+   Ninject（[`github.com/ninject/Ninject`](https://github.com/ninject/Ninject)）将所有内容绑定为依赖注入器。

+   我们使用简单的“肥”控制器，其中包含所有业务逻辑和数据访问层（因此没有存储库或其他设计模式）。这是特意选择的，以使应用程序尽可能紧凑。

+   大多数视图和控制器都基于标准的 MVC 5 脚手架，用于 EF 模型。

+   视图模型的使用仅限于绝对必要的地方。

您可以在该书的官方 GitHub 存储库中找到应用程序源代码，网址为[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/tree/master/Chapter10/01_voting-application-src`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/tree/master/Chapter10/01_voting-application-src)。要打开`VotingApplication.sln`解决方案文件，您需要 Visual Studio 2019。也可以通过使用`docker build`命令执行构建，如下一小节所述。在本节结束时，您将拥有一个用于投票应用程序的 Docker 镜像，准备在 Kubernetes 中使用。您可以按照步骤进行，或选择使用 Docker Hub 上提供的现成镜像，网址为[`hub.docker.com/repository/docker/packtpubkubernetesonwindows/voting-application`](https://hub.docker.com/repository/docker/packtpubkubernetesonwindows/voting-application)。

# 使用环境变量注入配置

在开发容器友好的应用程序时，您需要考虑如何注入配置数据，例如数据库连接字符串。一个经验法则是，您不应该将任何地址、用户名、密码或连接字符串硬编码到您的代码中。您应该始终能够在运行时注入这样的配置，并且一般来说，非容器化应用程序也是如此。Kubernetes 为您提供了多种方法来注入运行时配置，如下所示：

+   向容器命令传递参数

+   为容器定义系统环境变量

+   将 ConfigMaps 或 Secrets 挂载为容器卷

+   可选地使用 PodPresets 封装所有内容

您可以在官方文档中了解更多关于它们的信息（[`kubernetes.io/docs/tasks/inject-data-application/`](https://kubernetes.io/docs/tasks/inject-data-application/)）。重要的是，所有这些特性都使用标准的操作系统级原语，如文件或环境变量，与容器化应用程序集成。这意味着，如果您设计得当，您可以在 Kubernetes 内外不做任何更改地使用它。

我们将演示如何使用环境变量将 MSSQL Server 连接字符串注入到我们的应用程序中。这种方法是最简单的，但它有一个重要的限制——当容器正在运行时，您无法修改容器的环境变量。一旦设置了变量，它将在整个容器生命周期内保持相同的值。如果您需要能够在不重新启动容器的情况下修改配置，您应该看一下 ConfigMaps（与 Secrets 结合使用），这在下一章节中描述：第十一章，*配置应用程序以使用 Kubernetes 功能*。

我们的投票应用程序使用`VotingApplicationContextFactory`类来为**Model-View-Controller**（MVC）控制器创建 EF DbContext。让我们来看看这个类的`Create()`方法（可在[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter10/01_voting-application-src/Factories/VotingApplicationContextFactory.cs`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter10/01_voting-application-src/Factories/VotingApplicationContextFactory.cs)找到）。

```
public object Create(IContext context)
{
 var connectionString = Environment.GetEnvironmentVariable("CONNECTIONSTRING_VotingApplication");
 if (!string.IsNullOrEmpty(connectionString))
 {
 var safeConnectionString = SanitizeConnectionString(connectionString);
 this.log.Info("Using custom connection string provided by environment variable: {0}", safeConnectionString);
 return new VotingApplicationContext(connectionString);
 }

 this.log.Info("Using default connection string");
 return new VotingApplicationContext();
}
```

以下是您可以使用的一种常见模式，特别是在 Linux 世界中，那里更常依赖于环境变量：

1.  检查您选择的环境变量`CONNECTIONSTRING_VotingApplication`是否已定义。

1.  如果是，使用变量中的重写连接字符串创建 EF DbContext。

1.  如果没有，使用标准连接字符串创建 EF DbContext。在这种情况下，它将从`Web.config`应用程序文件中检索。

您可以遵循这种模式，特别是当您不使用自定义配置文件时。这种解决方案为您提供了很大的灵活性，您也可以在不使用容器运行应用程序时使用它！

另一种方法是将整个`Web.config`文件作为 Kubernetes ConfigMap 对象注入。我们将在下一章中探讨这种可能性。

这显示了一个重要的原则，即在容器化任何应用程序时应该考虑应用程序（系统）的外部接口以及它如何与外部世界通信。这是您可以影响或监视在容器中运行的应用程序的唯一方法。提供和注入配置是您的应用程序的外部接口之一。同样，日志记录为您的应用程序定义了一个输出接口，让我们看看您如何在 Windows 容器中处理这个问题。

# 为 Windows 容器配置日志记录日志监视器

Kubernetes 本身提供了简单的工具来浏览 Pod 容器日志。通常情况下，您将不得不实现一个良好的集群级日志记录解决方案，例如使用 Elasticsearch、Logstash、Kibana 堆栈或使用 Azure Log Analytics（如前几章中简要演示的）。官方文档对日志记录解决方案的可能架构进行了很好的概述：[`kubernetes.io/docs/concepts/cluster-administration/logging/`](https://kubernetes.io/docs/concepts/cluster-administration/logging/)。在所有情况下，您都需要将容器中的应用程序日志暴露给外部世界。从高层次来看，有三种主要方法：

+   使用容器的标准输出(stdout)和标准错误(stderr)入口点，并让容器运行时处理日志记录。稍后可以使用节点级别的日志代理（例如 Fluentd、Elastic Beats 或 Logstash）来转发日志到任何外部日志解决方案。如果您的容器化应用程序默认将所有内容写入控制台输出，这种方法特别有效。

+   在您的应用程序 Pod 中使用额外的辅助容器，该容器从文件系统、事件日志或其他来源收集日志，并将其公开为 stdout 或直接传输到外部日志解决方案。如果您的应用程序将日志记录到容器内的多个目的地，这种方法非常有用。

+   将日志流嵌入到应用程序本身中。例如，在 C#应用程序中，您可以使用 log4net 和专用的 Elasticsearch appender ([`github.com/ptylenda/log4net.ElasticSearch.Async`](https://github.com/ptylenda/log4net.ElasticSearch.Async)) 来将日志流式传输到您的 Elasticsearch 集群。这种方法的限制最多——它会对外部日志系统产生严重依赖，并且可能会对性能产生影响，这种影响很难与应用程序本身的工作负载分离。

对于 Windows 应用程序，将日志记录到 stdout 并不常见，特别是对于旧应用程序以及在使用 Internet Information Services (IIS) 托管您的 Web 应用程序时。在大多数情况下，对于 Windows 来说，更常见的是使用 Event Tracing for Windows (ETW)、事件日志或自定义日志文件。例如，我们的投票应用程序是使用 IIS 进行托管的。此外，在容器化模式下运行时，IIS 不提供公开应用程序的 stdout 的功能。您必须依赖事件日志或自己的日志文件。除此之外，IIS 本身会在标准位置`c:\inetpub\logs`中公开额外的应用程序日志，并将其自己的事件流传输到 ETW。

您可以以两种方式处理投票应用程序的日志收集：

+   使用额外的边车容器运行，例如，Elastic Beats 或 Winlogbeat（[`www.elastic.co/products/beats/winlogbeat`](https://www.elastic.co/products/beats/winlogbeat)），它收集应用程序容器的所有日志并将其暴露给 stdout（[`www.elastic.co/guide/en/beats/filebeat/current/console-output.html`](https://www.elastic.co/guide/en/beats/filebeat/current/console-output.html)）或任何其他支持的输出。日志需要使用 Pod 内部容器之间的卷进行共享。

+   扩展容器镜像与最近发布的 Windows 容器日志监视器（[`github.com/microsoft/windows-container-tools`](https://github.com/microsoft/windows-container-tools)）。有关架构的更多详细信息可以在这里找到：[`techcommunity.microsoft.com/t5/Containers/Windows-Containers-Log-Monitor-Opensource-Release/ba-p/973947`](https://techcommunity.microsoft.com/t5/Containers/Windows-Containers-Log-Monitor-Opensource-Release/ba-p/973947)。该工具使用的方法与边车容器不同。在 Docker 镜像中，您不是直接启动应用程序，而是使用适当的 JSON 配置文件启动`LogMonitor.exe`，并将启动应用程序的命令行作为`LogMonitor.exe`的参数。换句话说，`LogMonitor.exe`充当应用程序进程的监督者，并将根据配置文件从不同来源收集的日志打印到 stdout。计划进一步扩展此解决方案以用于边车容器模式。

我们将使用日志监视器，因为它易于集成和配置。应用程序的 Dockerfile 的详细信息将在下一小节中显示。假设启动应用程序（在本例中为 IIS）的命令是`C:\ServiceMonitor.exe w3svc`，使用 Log Monitor 的一般模式是以以下方式自定义 Dockerfile：

```
WORKDIR /LogMonitor
COPY LogMonitor.exe LogMonitorConfig.json .
SHELL ["C:\\LogMonitor\\LogMonitor.exe", "powershell.exe"]

ENTRYPOINT C:\ServiceMonitor.exe w3svc
```

我们应用程序的`LogMonitoringConfig.json`文件（[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter10/01_voting-application-src/LogMonitorConfig.json`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter10/01_voting-application-src/LogMonitorConfig.json)）具有以下 JSON 配置：

```
{
  "LogConfig": {
    "sources": [
      {
        "type": "EventLog",
        "startAtOldestRecord": true,
        "eventFormatMultiLine": false,
        "channels": [
          {
            "name": "system",
            "level": "Error"
          }
        ]
      },
      {
        "type": "EventLog",
        "startAtOldestRecord": true,
        "eventFormatMultiLine": false,
        "channels": [
          {
            "name": "VotingApplication",
            "level": "Verbose"
          }
        ]
      },
      {
        "type": "File",
        "directory": "c:\\inetpub\\logs",
        "filter": "*.log",
        "includeSubdirectories": true
      },
      {
        "type": "ETW",
        "providers": [
          {
            "providerName": "IIS: WWW Server",
            "ProviderGuid": "3A2A4E84-4C21-4981-AE10-3FDA0D9B0F83",
            "level": "Information"
          },
          {
            "providerName": "Microsoft-Windows-IIS-Logging",
            "ProviderGuid ": "7E8AD27F-B271-4EA2-A783-A47BDE29143B",
            "level": "Information",
            "keywords": "0xFF"
          }
        ]
      }
    ]
  }
}
```

此配置文件订阅日志监视器到`系统`日志和 Windows 事件日志中的`VotingApplication`日志，监视`C:\inetpub\logs`中的日志，并收集 IIS 的 ETW 数据。事件日志中的`VotingApplication`日志包含我们应用程序中由 Serilog 生成的所有日志。这在`NinjectWebCommon`类中配置（[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter10/01_voting-application-src/App_Start/NinjectWebCommon.cs`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter10/01_voting-application-src/App_Start/NinjectWebCommon.cs)），在那里我们初始化了日志记录器的输出，如下所示：

```
private static void RegisterServices(IKernel kernel)
{
    Log.Logger = new LoggerConfiguration()
        .ReadFrom.AppSettings()
        .Enrich.FromLogContext()
        .WriteTo.EventLog(source: "VotingApplication", logName: "VotingApplication", manageEventSource: false)
        .CreateLogger();

    kernel.Bind<VotingApplicationContext>().ToProvider(typeof(VotingApplicationContextFactory)).InRequestScope();
    kernel.Bind<IDateTimeProvider>().To<DateTimeProvider>().InRequestScope();
}
```

请注意，由于 Windows 容器不在特权模式下运行，我们无法自动在事件日志中创建日志（`manageEventSource: false`）。这必须在构建时在 Dockerfile 中完成。

通过这个设置，我们的投票应用程序将把我们自己的所有日志，以及系统和 IIS 的日志一起打印到容器的 stdout 中。这意味着您可以使用`docker logs`命令（在运行独立容器时）或`kubectl logs`命令轻松地对它们进行调查。如果与 Azure Log Analytics 集成，您的日志将可以使用 Kusto 进行查询。

# 创建 Dockerfile

下一步是为我们的应用程序准备一个 Dockerfile。您可以查看官方文档，了解如何在 Dockerfile 中构建.NET Framework 应用程序的方法，网址为[`github.com/microsoft/dotnet-framework-docker/tree/master/samples/dotnetapp`](https://github.com/microsoft/dotnet-framework-docker/tree/master/samples/dotnetapp)。我们的 Dockerfile 必须包括以下步骤：

1.  恢复 NuGet 软件包。

1.  构建应用程序，最好使用发布配置文件到本地文件系统。

1.  复制用于应用 EF 迁移的工具（由 EF NuGet 软件包提供）。

1.  在事件日志中创建`VotingApplication`日志。

1.  复制日志监视器二进制文件和配置。

1.  将投票应用程序二进制文件复制到`C:\inetpub\wwwroot`以进行 IIS 托管。

我们需要更深入地讨论 EF 迁移的话题。在没有应用程序停机时间并且应用程序有多个副本的情况下应用 EF 数据库迁移是一个复杂的任务。您需要确保迁移可以回滚，并且数据库架构与旧版本和新版本的应用程序完全兼容。换句话说，不兼容的更改，比如重命名，必须特别处理，以使它们在各个步骤之间具有向后兼容性。这个过程的框架可能如下所示 - 例如，对于实体的列重命名：

1.  应用添加具有新名称的新列的数据库迁移。

1.  推出一个新版本的应用程序，对旧列和新列进行写入。读取应该使用旧列进行，因为它始终具有正确的数据。

1.  执行一个从旧列复制数据到新列的作业。

1.  推出一个新版本的应用程序，从新列中读取。

1.  推出一个新版本的应用程序，只写入新列。

1.  应用数据库迁移，删除旧列。

正如您所看到的，为在 Kubernetes 中运行的应用程序正确处理数据库迁移而不中断需要严格的规则和兼容性/回滚测试 - 我们已经将这个话题带到您的注意中，但详细的解决方案不在本书的范围之内。Spring 有一篇很好的文章解释了如何解决这个问题（[`spring.io/blog/2016/05/31/zero-downtime-deployment-with-a-database`](https://spring.io/blog/2016/05/31/zero-downtime-deployment-with-a-database)），Weaveworks 也有一篇专门针对 Kubernetes 的文章：[`www.weave.works/blog/how-to-correctly-handle-db-schemas-during-kubernetes-rollouts`](https://www.weave.works/blog/how-to-correctly-handle-db-schemas-during-kubernetes-rollouts)。

为了应用迁移，我们将使用相同的 Docker 镜像 - EF 数据库迁移是使用应用程序程序集和 EF 命令行工具应用的，我们将在镜像中提供。然后，迁移（和数据库种子）将使用适合运行一次性任务的 Kubernetes 作业来运行。在实际情况下，这应该被安排为您的**持续集成/持续部署**（**CI/CD**）过程的一部分，伴随着 Kubernetes 部署的推出。

投票应用程序包含一个名为`Dockerfile.production`的 Dockerfile（[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter10/01_voting-application-src/Dockerfile.production`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter10/01_voting-application-src/Dockerfile.production)），它的层基于我们刚刚总结的内容。让我们逐步分析它：

1.  Dockerfile 定义了一个多阶段构建，这意味着在整个构建过程中使用了多个基础镜像。第一阶段是 Web 应用程序构建，使用了一个`mcr.microsoft.com/dotnet/framework/sdk`镜像。这个镜像包含了所有不需要运行时的.NET Framework 构建工具。其代码如下所示：

```
FROM mcr.microsoft.com/dotnet/framework/sdk:4.8-windowsservercore-ltsc2019 AS build
ARG PUBLISH_PROFILE=DockerPublishProfile.pubxml
ARG BUILD_CONFIG=Release

WORKDIR /app

COPY *.sln ./
COPY *.csproj ./
COPY *.config ./
RUN nuget restore

COPY . .
RUN msbuild /p:DeployOnBuild=true /p:PublishProfile=$env:PUBLISH_PROFILE /p:Configuration=$env:BUILD_CONFIG
```

这些层的组织方式使得在构建过程中最大化了层缓存的利用——例如，只有在特定解决方案配置文件更改时才运行`nuget restore`。

1.  构建过程由标准的`msbuild`命令执行，使用了一个名为`DockerPublishProfile.pubxml`的专用发布配置文件，其形式如下：

```
<Project ToolsVersion="4.0" >
  <PropertyGroup>
    <WebPublishMethod>FileSystem</WebPublishMethod>
    <PublishProvider>FileSystem</PublishProvider>
    <LastUsedBuildConfiguration>Release</LastUsedBuildConfiguration>
    <LastUsedPlatform>Any CPU</LastUsedPlatform>
    <SiteUrlToLaunchAfterPublish />
    <LaunchSiteAfterPublish>True</LaunchSiteAfterPublish>
    <ExcludeApp_Data>False</ExcludeApp_Data>
    <publishUrl>obj\Docker\publish</publishUrl>
    <DeleteExistingFiles>True</DeleteExistingFiles>
  </PropertyGroup>
</Project>
```

原则上，它执行`FileSystem`发布到`obj\Docker\publish`，这稍后将用于创建最终镜像。

1.  接下来，我们基于专门用于运行时场景的`mcr.microsoft.com/dotnet/framework/aspnet`镜像开始第二个和最后一个构建阶段，如下所示：

```
FROM mcr.microsoft.com/dotnet/framework/aspnet:4.8-windowsservercore-ltsc2019 AS runtime

WORKDIR /ef6
COPY --from=build /app/packages/EntityFramework.6.3.0/tools/net45/any/ .
```

在第一步中，我们执行 EF6 迁移命令行工具的复制，这些工具是通过 EF NuGet 包提供的。关键在于使用`--from=build`参数从上一个阶段复制。

1.  接下来是为我们的投票应用程序创建一个专用的事件日志（这个要求在前面的小节中提到过），如下所示：

```
RUN powershell.exe -Command New-EventLog -LogName VotingApplication -Source VotingApplication
```

1.  复制`LogMonitor`二进制文件和配置，同时覆盖容器的 shell 命令，如下所示：

```
WORKDIR /LogMonitor
ADD https://github.com/microsoft/windows-container-tools/releases/download/v1.0/LogMonitor.exe .
COPY --from=build /app/LogMonitorConfig.json .
SHELL ["C:\\LogMonitor\\LogMonitor.exe", "powershell.exe"]
```

1.  将前一个阶段的`build`工件复制到`C:\inetpub\wwwroot`的 IIS 应用程序目录中，如下所示：

```
WORKDIR /inetpub/wwwroot
COPY --from=build /app/obj/Docker/publish/. .
```

1.  最后，将镜像的默认入口点定义为启动 IIS 服务的`ServiceMonitor.exe`。这是一个标准的方法，在`mcr.microsoft.com/dotnet/framework/aspnet`基础镜像中可以看到。唯一的区别是整个进程树将在日志监视器的监督下运行。其代码如下所示：

```
ENTRYPOINT C:\ServiceMonitor.exe w3svc
```

就是这样！Dockerfile 定义了 ASP.NET MVC 应用程序的完整构建过程——您可以选择性地扩展它，添加一个测试阶段，执行适当的测试。现在，让我们构建镜像并将其推送到镜像注册表。

# 构建和推送 Docker 镜像

这个过程的确切细节已在第三章中进行了介绍，*使用容器镜像*。简而言之，您可以在这里使用两种方法：

1.  在本地机器上执行镜像的手动构建并将其推送到公共 Docker Hub。目前，在 Docker Hub 上无法为 Windows 容器镜像设置自动构建。

1.  如果您有兴趣将自动构建和 GitHub 挂钩集成到您的应用程序中，您可以使用**Azure 容器注册表**（**ACR**），如前面提到的章节中所述。

为了简单起见，我们将执行手动构建并将镜像推送到 Docker Hub。在实际情况下，您应该至少在 CI/CD 流水线中使用带有 GitHub 集成的 ACR。让我们执行 Docker 镜像的构建——在示例中，我们将使用`packtpubkubernetesonwindows/voting-application`镜像仓库名称，但如果您在跟随操作，应该使用您自己的`<dockerId>/voting-application`仓库。执行以下步骤：

1.  打开 PowerShell 窗口，导航到主`voting-application`源目录。

1.  使用以下命令执行 Docker 构建（记住最后的句点，它指定了构建上下文目录）：

```
docker build -t packtpubkubernetesonwindows/voting-application -f .\Dockerfile.production .
```

1.  等待构建完成，并相应地标记镜像。这对于 Kubernetes 部署至关重要，因为我们可以指定要推出的镜像的特定版本（使用最新版本会产生歧义，通常不建议使用）。建议使用语义版本控制，如第三章中所述的*使用容器镜像*，并且在以下代码块中进行了说明：

```
docker tag packtpubkubernetesonwindows/voting-application:latest packtpubkubernetesonwindows/voting-application:1.0.0
docker tag packtpubkubernetesonwindows/voting-application:latest packtpubkubernetesonwindows/voting-application:1.0
docker tag packtpubkubernetesonwindows/voting-application:latest packtpubkubernetesonwindows/voting-application:1
```

1.  将所有标记推送到镜像仓库，如下所示：

```
docker push packtpubkubernetesonwindows/voting-application
```

1.  现在，您可以验证 Docker Hub 页面上的标记是否正确可见，例如，[`hub.docker.com/repository/docker/packtpubkubernetesonwindows/voting-application/tags?page=1`](https://hub.docker.com/repository/docker/packtpubkubernetesonwindows/voting-application/tags?page=1)。

此时，我们的 Docker 镜像可以在本地使用（您需要使用环境变量提供有效的连接字符串到 SQL Server），也可以在 Kubernetes 中使用。让我们开始准备 AKS Engine 集群部署！

# 准备 AKS Engine

如果您已经按照第八章 *部署混合 Azure Kubernetes 服务引擎集群*创建了一个混合 Windows/Linux Kubernetes 集群，并且已经准备就绪，您可以在本节中验证集群的拓扑是否符合要求。如果您还没有部署 AKS Engine 集群，我们将在书籍的 GitHub 存储库中提供一个快速部署的 PowerShell 脚本。

我们的投票应用程序可以托管在尽可能小的混合 Windows/Linux 集群上，一个 Linux 主节点和一个 Windows 节点，其中 Linux 主节点充当常规节点。然而，为了充分演示部署的原则，我们将使用一个类似于生产环境的集群：一个运行在**虚拟机规模集**（**VMSS**）**高可用性**（**HA**）模式下的 Linux 主节点，两个 Linux 节点和两个 Windows 节点。我们在上一章中已经使用了这种配置来部署 AKS Engine 集群。为了快速从头部署 AKS Engine 集群，您可以执行以下步骤：

1.  从书籍的 GitHub 存储库下载以下 PowerShell 脚本：[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter08/01_aks-engine/01_CreateAKSEngineClusterWithWindowsNodes.ps1`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter08/01_aks-engine/01_CreateAKSEngineClusterWithWindowsNodes.ps1)。

1.  在 PowerShell 窗口中，使用适当的参数执行脚本，如下所示：

```
.\01_CreateAKSEngineClusterWithWindowsNodes.ps1 `
 -azureSubscriptionId <subscriptionId> `
 -dnsPrefix <globallyUniqueDnsPrefix> `
 -windowsPassword <windowsNodesPassword>
```

1.  该脚本将在 Azure 中使用`aks-engine-windows-resource-group`资源组将集群部署到 West Europe 位置。如果 AKS Engine 部署出现问题，您可以尝试指定不同的区域，例如`-azureLocation westus`。

1.  当部署完成后，您需要确保您的默认 kubeconfig 包含新集群的上下文。您可以通过使用以下命令快速合并由 AKS Engine 为 West Europe 位置生成的 kubeconfig 与默认 kubeconfig（在覆盖默认配置文件之前，请记得仔细检查`config_new`文件的内容，以避免任何丢失）：

```
$env:KUBECONFIG=".\_output\<globallyUniqueDnsPrefix>\kubeconfig\kubeconfig.westeurope.json;$env:USERPROFILE\.kube\config"
kubectl config view --raw > $env:USERPROFILE\.kube\config_new
 Move-Item -Force $env:USERPROFILE\.kube\config_new $env:USERPROFILE\.kube\config
```

1.  在新的 PowerShell 窗口中，通过运行以下命令来验证您是否能够访问集群，例如：

```
kubectl get nodes
```

运行这种规模的 AKS Engine 集群可能成本高昂，因此您应该始终检查**虚拟机**（**VM**）托管的预估成本。如果您不再需要该集群，可以使用`az group delete --name aks-engine-windows-resource-group --yes`命令来简单地删除它，也可以选择提供`--no-wait`参数。

此时，您已经准备好运行 Microsoft SQL Server 2019 和投票应用程序的集群，所以让我们继续！

# 部署故障转移 Microsoft SQL Server 2019

从 MSSQL Server 2017 开始，可以将其托管在 Linux Docker 容器中。由于我们的应用程序需要 MSSQL Server 进行数据持久化，因此我们将部署最新版本的 MSSQL Server 2019 到我们的 Kubernetes 集群中。目前，可以以以下两种模式将 MSSQL Server 部署到 Kubernetes 中：

1.  一个单节点实例，故障转移由 Kubernetes 部署和 Azure 磁盘持久卷保证。

1.  使用专用的 Kubernetes 操作员（[`kubernetes.io/docs/concepts/extend-kubernetes/operator/`](https://kubernetes.io/docs/concepts/extend-kubernetes/operator/)）的多节点 HA 集群。

第二种模式在**社区技术预览**（**CTP**）2.0 版本中作为预览版本发布（[`cloudblogs.microsoft.com/sqlserver/2018/12/10/availability-groups-on-kubernetes-in-sql-server-2019-preview/`](https://cloudblogs.microsoft.com/sqlserver/2018/12/10/availability-groups-on-kubernetes-in-sql-server-2019-preview/)），但目前，在**一般可用性**（**GA**）版本中，Docker 镜像和 Kubernetes 清单不兼容。如果您感兴趣，可以在[`github.com/microsoft/sql-server-samples/tree/master/samples/features/high%20availability/Kubernetes/sample-manifest-files`](https://github.com/microsoft/sql-server-samples/tree/master/samples/features/high%20availability/Kubernetes/sample-manifest-files)上检查此类部署的官方清单文件。

因此，我们将以更简单的单节点故障转移模式部署 SQL Server。要做到这一点，请执行以下步骤：

1.  打开 PowerShell 窗口。

1.  为新的 Kubernetes 命名空间创建一个`dev.yaml`清单文件，内容如下，并使用`kubectl apply -f .\dev.yaml`命令应用它：

```
kind: Namespace
apiVersion: v1
metadata:
  name: dev
  labels:
    name: dev
```

1.  为使用 Azure Disk provisioner 的 Kubernetes 存储类创建一个`storage-class.yaml`清单文件，并使用`kubectl apply -f .\storage-class.yaml`命令应用它，如下所示：

```
kind: StorageClass
apiVersion: storage.k8s.io/v1beta1
metadata:
  name: azure-disk
provisioner: kubernetes.io/azure-disk
parameters:
  storageaccounttype: Standard_LRS
  kind: Managed
```

1.  创建一个`pvc.yaml`清单文件，为 SQL Server 实例定义一个`mssql-data`**持久卷索赔**（**PVC**）。这个 PVC 将用于在容器中的`/var/opt/mssql`中挂载数据。使用`kubectl apply -f .\pvc.yaml`命令应用该清单，如下所示：

```
kind: PersistentVolumeClaim
apiVersion: v1
metadata:
  namespace: dev
  name: mssql-data
  annotations:
    volume.beta.kubernetes.io/storage-class: azure-disk
spec:
  accessModes:
  - ReadWriteOnce
  resources:
    requests:
      storage: 8Gi
```

1.  定义一个 Kubernetes `mssql` Secret，其中包含 SQL Server 的**系统管理员**（**SA**）用户密码，使用您自己的安全密码，如下所示：

```
kubectl create secret generic -n dev mssql --from-literal=SA_PASSWORD="S3cur3P@ssw0rd"
```

1.  创建一个`sql-server.yaml`清单文件，为 SQL Server 定义 Kubernetes 部署，如下所示：

```
kind: Deployment
apiVersion: apps/v1
metadata:
  namespace: dev
  name: mssql-deployment
spec:
  replicas: 1
  selector:
    matchLabels:
      app: mssql
  template:
    metadata:
      labels:
        app: mssql
    spec:
      terminationGracePeriodSeconds: 10
      initContainers:
      - name: volume-mount-permissions-fix  # (1)
        image: busybox
        command: ["sh", "-c", "chown -R 10001:0 /var/opt/mssql"]
        volumeMounts:
        - name: mssqldb
          mountPath: /var/opt/mssql
      containers:
      - name: mssql
        image: mcr.microsoft.com/mssql/server:2019-GA-ubuntu-16.04
        ports:
        - containerPort: 1433
        env:
        - name: MSSQL_PID  # (2)
          value: "Developer"
        - name: ACCEPT_EULA
          value: "Y"
        - name: MSSQL_SA_PASSWORD  # (3)
          valueFrom:
            secretKeyRef:
              name: mssql
              key: SA_PASSWORD  # (4)
        volumeMounts:  # (5)
        - name: mssqldb
          mountPath: /var/opt/mssql
      volumes:
      - name: mssqldb
        persistentVolumeClaim:
          claimName: mssql-data
      nodeSelector:
        "beta.kubernetes.io/os": linux
```

这个清单文件有几个重要部分，如下所示：

1.  首先，我们需要一个额外的`volume-mount-permissions-fix`初始化容器，这是为了确保在挂载 PVC 后，目录对于 SQL Server 有适当的访问权限——该容器将在常规 Pod 容器创建之前运行。这是如何使用初始化容器的一个很好的例子。

1.  其次，我们需要接受**最终用户许可协议**（**EULA**），使用`ACCEPT_EULA`环境变量，并选择适当的 SQL Server 版本，使用`MSSQL_PID`环境变量。

1.  我们将使用 Developer 版本，因为我们的应用仅用于开发目的。您可以在图像的文档中阅读有关这些变量使用的更多信息，网址为[`hub.docker.com/_/microsoft-mssql-server`](https://hub.docker.com/_/microsoft-mssql-server)。此外，您需要提供一个`MSSQL_SA_PASSWORD`环境变量，其中包含实例的 SA 用户密码。

1.  为此，我们使用了之前创建的`mssql` Secret 中的值。

1.  接下来，我们需要将`mssql-data` PVC 提供的卷挂载到`/var/opt/mssql`路径。

1.  这将提供类似于 SQL Server 共享磁盘故障转移实例的故障转移。最后，我们必须确保`nodeSelector`设置为仅选择 Linux 机器。

现在，继续使用以下步骤进行部署：

1.  使用`kubectl apply -f .\sql-server.yaml`命令应用清单文件。

1.  创建一个`sql-server-service.yaml`清单文件，为您的 SQL Server 实例创建一个 Kubernetes 服务。根据您的需求，您可以使用`ClusterIP`类型，或者，如果您将 SQL Server 实例暴露给 Kubernetes 集群外的连接（例如，用于**SQL Server Management Studio**（**SSMS**）），您可以使用`LoadBalancer`类型。使用`kubectl apply -f .\sql-server-service.yaml`命令应用清单文件，如下所示：

```
kind: Service
apiVersion: v1
metadata:
  namespace: dev
  name: mssql-deployment
spec:
  selector:
    app: mssql
  ports:
    - protocol: TCP
      port: 1433
      targetPort: 1433
  type: LoadBalancer
```

1.  您可以使用以下命令观察 Pod 的创建：

```
PS C:\src> kubectl get pods -n dev --watch
NAME                                READY   STATUS    RESTARTS   AGE
mssql-deployment-58bcb8b89d-7f9xz   1/1     Running   0          8m37s
```

此时，在`dev`命名空间中运行着一个 MSSQL Server 2019 实例，可以在集群内部使用`mssql-deployment`的**域名系统**（**DNS**）名称进行访问。此外，如果您创建了一个 LoadBalancer 服务，可以使用 SSMS 验证实例，提供服务的外部 IP 地址、用户 SA 和您选择的密码。

现在我们可以继续创建投票应用程序的清单文件，并将应用程序部署到集群中。

# 部署 ASP.NET MVC 应用程序

最后，是大秀的时刻！我们将使用标准的 Kubernetes 部署现在部署我们的投票应用程序，并在下一节中使用 LoadBalancer 服务将其暴露给外部用户。首先，我们需要简要总结我们的应用程序的正确部署所需的内容，如下所示：

+   将使用`packtpubkubernetesonwindows/voting-application:1.0.0` Docker 镜像来部署该应用程序。如果您已将图像推送到自己的图像存储库，则需要相应更改清单文件。我们明确指定`1.0.0`标签，因为我们希望避免拉取意外的容器图像版本。您可以在文档中阅读有关容器图像的最佳实践的更多信息[`kubernetes.io/docs/concepts/configuration/overview/#container-images`](https://kubernetes.io/docs/concepts/configuration/overview/#container-images)。

+   该应用程序需要设置`CONNECTIONSTRING_VotingApplication`环境变量，如果需要自定义连接字符串。在我们的部署情况下，连接字符串应具有以下形式：`Data Source=mssql-deployment;Initial Catalog=VotingApplication;MultipleActiveResultSets=true;User Id=sa;Password=$(MSSQL_SA_PASSWORD);`，其中`$(MSSQL_SA_PASSWORD)`将从 Kubernetes Secret 中检索。

+   应用初始数据库迁移是为了填充数据库数据。我们将使用 Kubernetes Job 来执行这个操作——这种方法可以在您的 CI/CD 流水线中进行泛化。迁移本身是使用`ef6.exe database update`命令执行的——镜像已经包含了这个可执行文件在`C:/ef6/`目录中。请注意，在生产环境中，您可能希望创建一个单独的 Docker 镜像，专门用于迁移，其中包含所有所需的工具。这样，您可以保持应用程序镜像的干净和尽可能小。

+   我们暂时不会创建专用的活跃性和就绪性探针，这将在下一章节中进行演示：第十一章，*配置应用程序使用 Kubernetes 功能*。

要部署投票应用程序，请执行以下步骤：

1.  打开 PowerShell 窗口。

1.  创建一个名为`voting-application.yaml`的 Kubernetes 部署清单文件，内容如下：

```
apiVersion: apps/v1
kind: Deployment
metadata:
  namespace: dev
  name: voting-application-frontend
  labels:
    app: voting-application
spec:
  replicas: 5  # (1)
  minReadySeconds: 5  # (2)
  strategy:  # (3)
    type: RollingUpdate
    rollingUpdate:
      maxUnavailable: 25%
      maxSurge: 25%
  selector:
    matchLabels:
      app: voting-application
  template:
    metadata:
      name: voting-application-frontend
      labels:
        app: voting-application
    spec:
      nodeSelector:  # (4)
        "beta.kubernetes.io/os": windows
      containers:
      - name: frontend
        image: packtpubkubernetesonwindows/voting-application:1.0.0  # (5)
        env:
        - name: MSSQL_SA_PASSWORD  # (6b)
          valueFrom:
            secretKeyRef:
              name: mssql
              key: SA_PASSWORD  # (6a)
        - name: CONNECTIONSTRING_VotingApplication  # (6c)
          value: "Data Source=mssql-deployment;Initial Catalog=VotingApplication;MultipleActiveResultSets=true;User Id=sa;Password=$(MSSQL_SA_PASSWORD);"
        ports:
          - containerPort: 80
        resources:
          limits:
            cpu: 500m
          requests:
            cpu: 500m
```

让我们解释一下这个清单文件中最重要的部分：

1.  我们将其定义为一个具有`5`个初始副本的部署——在我们的情况下，前端应用程序是无状态的，因此我们可以根据需要进行扩展。

1.  为了防止 IIS 仍在初始化的 Pod 被访问，我们添加了`minReadySeconds: 5`，以便有一个简单的机制。在下一章中，我们将配置适当的就绪性和活跃性探针。

1.  我们还明确将部署更新策略设置为`RollingUpdate`，最大不可用 Pod 数量为`25%`，允许我们在部署过程中创建多达预期数量的`25%`的 Pod（这由`maxSurge`参数控制）。

1.  接下来，记得设置适当的`nodeSelector`，只部署到 Windows 节点。

1.  指定要使用特定标签的镜像——如果使用自己的镜像，相应地更新它。

1.  为了创建数据库的连接字符串，我们必须首先从`mssql` Secret `(6a)`中检索 SA 用户密码，并初始化`MSSQL_SA_PASSWORD`环境变量`(6b)`，该变量可用于创建存储在`CONNECTIONSTRING_VotingApplication`变量中的实际连接字符串（6c）。正如所示，您可以使用现有环境变量来初始化新的环境变量：`Data Source=mssql-deployment;Initial Catalog=VotingApplication;MultipleActiveResultSets=true;User Id=sa;Password=$(MSSQL_SA_PASSWORD);`。当您想要从 Secret 中检索值并用它来定义另一个变量时，这是一种常见的模式。

现在，请按以下步骤继续部署：

1.  使用`kubectl apply -f .\voting-application.yaml`命令应用清单文件。等待 Pod 启动，如下所示：

```
PS C:\src> kubectl get pods -n dev
NAME                                           READY   STATUS    RESTARTS   AGE
mssql-deployment-58bcb8b89d-7f9xz              1/1     Running   0          19h
voting-application-frontend-6876dcc678-kdmcw   1/1     Running   0          19m
voting-application-frontend-6876dcc678-mhdr9   1/1     Running   0          19m
voting-application-frontend-6876dcc678-qsmst   1/1     Running   0          19m
voting-application-frontend-6876dcc678-w5hch   1/1     Running   0          19m
voting-application-frontend-6876dcc678-zqr26   1/1     Running   0          19m
```

应用程序已成功部署。在访问之前，我们首先需要应用初始数据库迁移——从技术上讲，您可以在不播种数据库的情况下访问应用程序，因为架构将自动初始化，但表中将没有任何数据。要执行数据库迁移，请执行以下步骤：

1.  为 Kubernetes Job 创建一个名为`ef6-update-database.yaml`的清单文件，内容如下：

```
apiVersion: batch/v1
kind: Job
metadata:
  namespace: dev
  name: voting-application-ef6-update-database3
  labels:
    app: voting-application
spec:
  ttlSecondsAfterFinished: 600  # (1)
  template:
    spec:
      nodeSelector:  # (2)
        "beta.kubernetes.io/os": windows
      containers:
      - name: ef6-update-database
        image: packtpubkubernetesonwindows/voting-application:1.0.0  # (3)
        command: ["c:/ef6/ef6.exe",  # (4)
                  "database", "update", 
                  "--verbose",
                  "--assembly", "/inetpub/wwwroot/bin/VotingApplication.dll",
                  "--connection-string", "Data Source=mssql-deployment;Initial Catalog=VotingApplication;MultipleActiveResultSets=true;User Id=sa;Password=$(MSSQL_SA_PASSWORD);",
                  "--connection-provider", "System.Data.SqlClient",
                  "--config", "/inetpub/wwwroot/Web.config"]
        env:
        - name: MSSQL_SA_PASSWORD
          valueFrom:
            secretKeyRef:
              name: mssql
              key: SA_PASSWORD
      restartPolicy: Never
      nodeSelector:
        "beta.kubernetes.io/os": windows
  backoffLimit: 4
```

关键点在于设置**生存时间**（**TTL**）秒值，以便触发作业创建的 Pod 的自动清理`(1)`，并确保 Pod 在 Windows 节点上执行`(2)`。最后一部分是设置容器镜像`(3)`。在我们的情况下，我们使用与应用程序相同的镜像，因为它包含所有迁移工具。`(4)`命令是特定于 EF 的，但通常情况下，您必须使用`--assembly`参数提供包含迁移的.NET 程序集的路径，并使用`--connection-string`参数提供适当的连接字符串。

1.  使用`kubectl apply -f .\ef6-update-database.yaml`命令应用清单文件。

1.  等待作业运行完成，如下所示：

```
PS C:\src> kubectl get jobs -n dev
NAME                                      COMPLETIONS   DURATION   AGE
voting-application-ef6-update-database    1/1           50s        103s
```

1.  您可以使用标准的`kubectl logs`命令检查日志，但是您必须提供`jobs`前缀，如下所示：

```
PS C:\src> kubectl logs -n dev jobs/voting-application-ef6-update-database
Specify the '-Verbose' flag to view the SQL statements being applied to the target database.
Target database is: 'VotingApplication' (DataSource: mssql-deployment, Provider: System.Data.SqlClient, Origin: Explicit).
No pending explicit migrations.
Applying automatic migration: 201911201840183_AutomaticMigration.
CREATE TABLE [dbo].[Options] (
...
```

1.  现在，如果出现任何问题，例如您无法访问日志（因为 Pod 甚至没有启动）或所有作业执行都以失败结束，最好的调查方法是描述作业对象并找到它创建的 Pod，如下所示：

```
PS C:\src> kubectl describe job -n dev voting-application-ef6-update-database
...
Events:
 Type    Reason            Age    From            Message
 ----    ------            ----   ----            -------
 Normal  SuccessfulCreate  6m23s  job-controller  Created pod: voting-application-ef6-update-database-chw6s
```

1.  使用这些信息，您可以描述任何未正确启动的 Pod，或者甚至可以直接使用作业名称描述它们，如下所示：

```
kubectl describe pod -n dev voting-application-ef6-update-database
```

我们的应用程序已经准备就绪 - 即使尚未为其创建 LoadBalancer 服务。为此，我们将使用前几章中描述的技术，如下所示：

1.  在 PowerShell 窗口中，执行以下命令，将所有网络流量从本地主机端口`5000`转发到`voting-application`部署中一个 Pod 的端口`80`，如下所示：

```
PS C:\src> kubectl port-forward -n dev deployment/voting-application-frontend 5000:80
Forwarding from 127.0.0.1:5000 -> 80
Forwarding from [::1]:5000 -> 80
```

1.  在不关闭 PowerShell 会话的情况下，打开您的网络浏览器并导航到`http://localhost:5000`。您应该会看到以下屏幕：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/c72677f2-25c3-4819-8028-626c9c94f3fb.png)

恭喜！您已成功部署了投票应用程序 - 现在，我们可以继续使用 LoadBalancer 服务公开部署。

# 访问应用程序

在本节中，我们将通过创建 LoadBalancer 类型的 Kubernetes 服务，向外部用户公开我们的投票应用程序。服务在第五章中已经进行了深入讨论，*Kubernetes 网络*。在本节结束时，任何拥有您的新服务的外部 IP 的人都将能够访问该应用程序。

要创建服务，请执行以下步骤：

1.  打开 PowerShell 窗口。

1.  为 Kubernetes 服务创建`voting-application-service.yaml`清单文件，内容如下：

```
apiVersion: v1
kind: Service
metadata:
  namespace: dev
  name: voting-application-frontend
  labels:
    app: voting-application
spec:
  type: LoadBalancer (1)
  ports:
  - protocol: TCP
    port: 80 (2)
  selector:
    app: voting-application
```

在这里，关键点是确保服务类型为`LoadBalancer (1)`，并为服务使用正确的端口`(2)`。在我们的情况下，物理 Azure 负载均衡器上的端口将与应用程序 Pod 的端口相同，因此我们不需要指定`targetPort`参数。

1.  使用`kubectl apply -f .\voting-application-service.yaml`命令应用清单文件。

1.  等待为新服务提供外部 IP，如下所示：

```
PS C:\src> kubectl get svc -n dev -w
NAME                          TYPE           CLUSTER-IP     EXTERNAL-IP      PORT(S)          AGE
mssql-deployment              LoadBalancer   10.0.134.237   104.210.54.75    1433:31446/TCP   21h
voting-application-frontend   LoadBalancer   10.0.50.43     104.42.142.217   80:32357/TCP     62s
```

1.  在这种情况下，外部 IP 是`104.42.142.217`。使用您的网络浏览器并导航到`http://104.42.142.217`。

1.  您可以尝试多次刷新页面，并从不同的浏览器访问。您将在页面页脚看到您被不同的 Pod 提供服务。如果您在开始时遇到任何延迟，那是因为当第一次访问时，IIS 启动了给定 Pod 中的应用程序池。代码可以在以下片段中看到：

```
Served by: voting-application-frontend-6876dcc678-zqr26 (10.240.0.44)
```

现在应用程序对所有外部用户都是可访问的！现在，我们将看看如何扩展应用程序。

# 扩展应用程序

在我们的设计中，唯一可以扩展的组件是 ASP.NET MVC 前端。SQL Server 无法扩展，因为它在单个节点上以自动故障转移模式运行。真正扩展 SQL Server 需要使用**可用性组**（**AG**）和专用的 Kubernetes Operator，如前面的部分所述。

在上一章中，我们展示了不同的声明性和命令式方法，介绍了如何扩展部署。现在我们将展示最安全的、声明性的扩展部署的方法。自动扩展将不在此处涵盖，因为它在下一章中有更详细的描述：第十一章，*配置应用程序以使用 Kubernetes 功能*。要将前端部署从 5 个副本扩展到 10 个，请执行以下步骤：

1.  打开 PowerShell 窗口。

1.  修改您现有的`voting-application.yaml`清单文件，更改副本的数量，如下所示：

```
apiVersion: apps/v1
kind: Deployment
metadata:
  ...
spec:
  replicas: 10
```

1.  使用`kubectl apply -f .\voting-application.yaml`命令应用清单文件。

1.  观察滚动的状态，如下面的代码块所示：

```
PS C:\src> kubectl get deployments -n dev -w
NAME                          READY   UP-TO-DATE   AVAILABLE   AGE
mssql-deployment              1/1     1            1           21h
voting-application-frontend   6/10    10           5           125m
```

1.  最终您会发现它永远不会达到 10 个就绪的副本！发生了什么？答案是我们已经耗尽了两个 Windows 节点的 CPU 预留限制——每个节点都安排了四个 Pod，每个 Pod 预留了`500m`的 CPU。如果您检查 Standard_D2_v3 Azure VM 的规格，您会发现它有两个 vCPU，这意味着我们已经预留了所有资源。您可以通过检查处于`Pending`状态的 Pod 来验证这个理论，如下所示：

```
PS C:\src> kubectl get pods -n dev
NAME                                            READY   STATUS      RESTARTS   AGE
...
voting-application-frontend-6876dcc678-9ssc4    0/1     Pending     0          6m1s
...
```

1.  描述处于`Pending`状态的一个 Pod，如下所示：

```
PS C:\src> kubectl describe pod -n dev voting-application-frontend-6876dcc678-9ssc4
Events:
 Type     Reason            Age        From               Message
 ----     ------            ----       ----               -------
 Warning  FailedScheduling  <unknown>  default-scheduler  0/5 nodes are available: 2 Insufficient cpu, 3 node(s) didn't match node selector.
```

在这种情况下，我们可以做什么？考虑以下选项：

+   通过添加更多的 Windows 节点来扩展您的 Kubernetes 集群。

+   不要扩展集群；减少部署的 CPU 限制。

+   不要扩展集群；不要更改部署的 CPU 限制，而是减少 CPU 请求以进行超额分配。您可以通过查看官方文档深入了解这个概念：[`kubernetes.io/docs/concepts/configuration/manage-compute-resources-container/#how-pods-with-resource-limits-are-run`](https://kubernetes.io/docs/concepts/configuration/manage-compute-resources-container/#how-pods-with-resource-limits-are-run)。

一般来说，为了决定要做什么，您必须了解应用程序的要求以及在低 CPU 可用性下的行为。作为演示，我们将执行 CPU 资源的超额分配，如下所示：

1.  修改`voting-application-service.yaml`清单文件。

1.  将请求的 CPU 值更改为`250m`，保持限制值不变。请注意，我们还需要修改`maxUnavailable`以允许在部署期间不可用的 Pods 数量更多。使用先前的`25%`值，我们将遇到死锁情况，因为已经有 10 个 Pod 中的 2 个不可用。此代码如下所示：

```
apiVersion: apps/v1
kind: Deployment
...
spec:
  strategy:
    ...
    rollingUpdate:
      maxUnavailable: 50%
  ...
  template:
    ...
    spec:
      ...
      containers:
      - name: frontend
        ...
        resources:
          limits:
            cpu: 500m
          requests:
            cpu: 250m
```

1.  使用`kubectl apply -f .\voting-application.yaml`命令应用清单文件，并观察部署如何扩展到 10 个副本。

现在您了解了如何扩展我们的投票应用程序，我们可以转到本章的最后一节，展示如何调试应用程序。

# 调试应用程序

调试应用程序是一个广泛的话题，涉及许多技术，具体取决于需求——可能涉及详细的遥测、跟踪或性能计数器分析。从开发者的角度来看，有一种技术特别重要：与代码调试器一起工作。容器化工作负载的一个问题是，使用诸如 Visual Studio 之类的标准工具进行调试相对较重——进程不在本地运行，您不能像本地进程一样轻松附加调试器。在本节中，我们将展示以下内容：

+   如何访问日志监视器生成的应用程序日志

+   如何通过`kubectl`端口转发启用 Visual Studio 远程调试

访问应用程序日志很简单，因为它涉及标准的`kubectl logs`命令。在生产场景中，您可能会使用 Azure Log Analytics 或 Elasticsearch 更有效地浏览日志。要访问投票应用程序日志，请执行以下命令，该命令将从部署中的所有 Pod 加载日志：

```
PS C:\src> kubectl logs -n dev deployment/voting-application-frontend
...
<Source>EventLog</Source><Time>2019-11-20T22:51:17.000Z</Time><LogEntry><Channel>VotingApplication</Channel><Level>Information</Level><EventId>55509</EventId><Message>Using custom connection string provided by environment variable: "data source=mssql-deployment;initial catalog=VotingApplication;multipleactiveresultsets=true;user id=sa;password=*****" </Message></LogEntry>
...
```

当前的日志设置非常详细，但您可以在 Windows 事件日志中看到 Serilog 记录的所有日志消息，例如前面的行来自`VotingApplicationContextFactory`类([`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter10/01_voting-application-src/Factories/VotingApplicationContextFactory.cs#L28`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter10/01_voting-application-src/Factories/VotingApplicationContextFactory.cs#L28))。

现在，让我们转向更复杂的情景，即通过`kubectl`端口转发进行 Visual Studio 远程调试。这种用例尚未有文档记录，但它涉及到从非容器化部署中已知的标准技术。我们将执行以下操作：

1.  为调试创建一个专用的 Docker 镜像，其中安装了 Visual Studio 2019 远程工具([`docs.microsoft.com/en-us/visualstudio/debugger/remote-debugging?view=vs-2019`](https://docs.microsoft.com/en-us/visualstudio/debugger/remote-debugging?view=vs-2019))。

1.  使用特殊标签将镜像推送到注册表。

1.  修改我们的部署，以使用新的镜像——对于生产情景，您可能更愿意创建一个单独的部署。

1.  从容器中复制**程序数据库**（**PDB**）符号文件。我们必须执行此步骤，因为在容器中构建应用程序可能会导致略有不同的输出程序集和符号。

1.  使用`kubectl`端口转发功能将远程调试器暴露给本地开发机。

1.  使用转发的远程调试器将 Visual Studio 附加到`w3wp.exe`进程。

1.  加载任何丢失的调试符号。

在我们的情景中，由于我们正在运行经典的.NET Framework，我们受限于传统的 Visual Studio 远程调试器。对于.NET Core，有更多的方法，涉及到 Visual Studio Enterprise 和 Visual Studio Code。您可以在[`github.com/Microsoft/vssnapshotdebugger-docker`](https://github.com/Microsoft/vssnapshotdebugger-docker)上阅读有关在 Linux 上运行的.NET Core 的 Visual Studio Enterprise 快照调试，以及使用 Azure Dev Spaces 的 Visual Studio Code 的更多信息[`microsoft.github.io/AzureTipsAndTricks/blog/tip228.html`](https://microsoft.github.io/AzureTipsAndTricks/blog/tip228.html)。

让我们从创建用于调试的修改后的 Dockerfile 开始。

# 创建一个调试 Dockerfile 并发布一个调试镜像。

为了创建一个调试 Dockerfile，我们将使用我们的原始`Dockerfile.production`文件并进行轻微修改。 结果文件是`Dockerfile.debug`（[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter10/01_voting-application-src/Dockerfile.debug`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter10/01_voting-application-src/Dockerfile.debug)）。 让我们总结其内容：

1.  Dockerfile 中的构建阶段看起来几乎相同-唯一的区别是我们正在使用调试配置进行构建。 这将确保我们生成了适当的调试程序集，以及 PDB 符号，如下所示：

```
FROM mcr.microsoft.com/dotnet/framework/sdk:4.8-windowsservercore-ltsc2019 AS build
ARG PUBLISH_PROFILE=DockerPublishProfileDebug.pubxml
ARG BUILD_CONFIG=Debug

WORKDIR /app

COPY *.sln ./
COPY *.csproj ./
COPY *.config ./
RUN nuget restore

COPY . .
RUN msbuild /p:DeployOnBuild=true /p:PublishProfile=$env:PUBLISH_PROFILE /p:Configuration=$env:BUILD_CONFIG
```

1.  在最终的构建阶段，我们首先下载并安装 Visual Studio 2019 远程工具。 我们正在公开端口`4020`，因为我们将使用该端口托管远程调试器，如下面的代码块所示：

```
FROM mcr.microsoft.com/dotnet/framework/aspnet:4.8-windowsservercore-ltsc2019 AS runtime

WORKDIR /temp
RUN powershell.exe -Command Invoke-WebRequest https://aka.ms/vs/16/release/RemoteTools.amd64ret.enu.exe -OutFile VS_RemoteTools.exe 
RUN powershell.exe -Command ./VS_RemoteTools.exe /install /quiet
EXPOSE 4020
```

1.  图像的其余部分保持不变，除了`ENTRYPOINT`。 我们修改它，以便远程调试器进程（`msvsmon.exe`）在后台启动。 原则上，在容器中在后台启动另一个进程并不是一种推荐的做法，但在我们的情况下，我们希望以最快的方式启动远程调试器以及其他服务。 此命令的语法是特定于 Powershell 的，并且可以在以下代码块中看到：

```
ENTRYPOINT Start-Process -NoNewWindow 'C:\Program Files\Microsoft Visual Studio 16.0\Common7\IDE\Remote Debugger\x64\msvsmon.exe' -ArgumentList /nostatus,/silent,/noauth,/anyuser,/nosecuritywarn,/port,4020; C:\ServiceMonitor.exe w3svc
```

调试 Dockerfile 准备就绪后，我们可以创建图像并将其推送到 Docker Hub。 请执行以下步骤：

1.  我们将使用一种约定，即调试图像的标记将在标记中带有`-debug`后缀-例如，对于生产标记 1.0.0，我们将使用调试标记`1.0.0-debug`。 另一种选择是为调试图像创建一个新的专用图像存储库。 要构建图像，请在投票应用程序源的根目录中执行以下命令（相应地使用您自己的图像存储库名称）：

```
docker build -t packtpubkubernetesonwindows/voting-application:1.0.0-debug -f .\Dockerfile.debug .
```

1.  构建完成后，将新图像推送到 Docker Hub，如下所示：

```
docker push packtpubkubernetesonwindows/voting-application:1.0.0-debug
```

图像推送后，我们准备推出应用程序的调试部署。

# 更新 Kubernetes 部署

如前所述，为了简单起见，我们将重用相同的 Kubernetes 部署和服务以启用调试。 我们需要对原始`voting-application.yaml`清单文件进行以下修改：

```
apiVersion: apps/v1
kind: Deployment
metadata:
  ...
spec:
  replicas: 1
  ...
  template:
    ...
    spec:
      ...
      containers:
      - name: frontend
        image: packtpubkubernetesonwindows/voting-application:1.0.0-debug
        imagePullPolicy: Always
```

将副本的数量修改为`1`，确保在调试时，我们只有一个 Pod 接收流量。这意味着我们可以轻松地使用调试器在**用户界面**（UI）中断任何操作。除此之外，我们还需要将镜像更新为我们的新`packtpubkubernetesonwindows/voting-application:1.0.0-debug`标签，并将`imagePullPolicy`设置为`Always`，以便更轻松地引入更改。例如，如果您发现了一个错误并希望快速重新部署镜像并重新连接，您可以使用相同的标签构建镜像，推送它，并手动删除部署中当前运行的 Pod。这将重新创建 Pod，并且由于`Always`策略，镜像将再次被拉取。

现在，使用`kubectl apply -f .\voting-application.yaml`命令应用清单文件。我们的设置已经准备好连接 Visual Studio 调试器。

# 连接 Visual Studio 远程调试器

最后一步是使用远程调试器将您的 Visual Studio 2019 连接到运行在容器内部的 IIS 应用程序池进程。这个过程并不是完全自动化的（但可以脚本化），并且可以进一步统一容器镜像和本地开发机器之间的 PDB 符号。要连接调试器，请执行以下步骤：

1.  打开 PowerShell 窗口。

1.  使用以下标准命令确定您的应用程序 Pod 的名称：

```
kubectl get pods -n dev
```

1.  使用`kubectl cp`命令将`VotingApplication.pdb`文件复制到当前目录，具体如下：

```
PS C:\src> kubectl cp -n dev voting-application-frontend-66b95ff674-mmsbk:/inetpub/wwwroot/bin/VotingApplication.pdb VotingApplication.pdb
tar: Removing leading '/' from member names
```

1.  或者，您可以在本地使用 Docker 执行此操作，通过创建临时容器并使用以下命令复制文件：

```
$id = $(docker create packtpubkubernetesonwindows/voting-application:1.0.0-debug)
docker cp $id`:/inetpub/wwwroot/bin/VotingApplication.pdb VotingApplication.pdb
docker rm -v $id
```

1.  使用`kubectl port-forward`命令将所有流量从本地的`5000`端口转发到 Pod 中的`4020`端口，这是 Visual Studio 远程调试器暴露的地方，具体如下：

```
PS C:\src> kubectl port-forward -n dev deployment/voting-application-frontend 5000:4020
Forwarding from 127.0.0.1:5000 -> 4020
Forwarding from [::1]:5000 -> 4020
```

1.  现在，您已经准备好将 Visual Studio 2019 连接到远程调试器。在 Visual Studio 中打开`VotingApplication.sln`，并导航到调试 > 附加到进程...，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/1dae82b3-48ba-4d1a-bc72-456bf4ed43ed.png)

1.  在对话框中，将连接类型设置为远程（无身份验证），将连接目标设置为转发端口`localhost:5000`，选择显示所有用户的进程，并单击刷新按钮，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/6d9f7929-e738-4a6b-bf3b-7420926c5eee.png)

1.  您应该看到容器中运行的所有进程列表。如果在这一点上遇到连接问题，您可以在 Kubernetes 中执行进入容器，并检查`msvsmon.exe`进程是否仍在运行。如果没有，您可以重新创建容器或使用与 Dockerfile 中相同的命令手动启动进程，就像这样：

```
PS C:\src> kubectl exec -n dev -it voting-application-frontend-66b95ff674-vn256 powershell
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.
PS C:\inetpub\wwwroot> Get-Process
...
 218      12     2240       9016       0.06  12360   2 msvsmon
```

1.  现在，在浏览器中导航到服务的外部 IP。我们需要确保 IIS 应用程序池进程（`w3wp.exe`）已启动。

1.  在“附加到进程”对话框中，刷新进程列表，找到`w3wp.exe`进程，并单击“附加”按钮，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/8cbca376-ce7f-4fb1-924d-b04e0a128064.png)

1.  调试器已附加，但可能缺少符号。您可以通过在代码的任何位置设置断点来验证这一点，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/3d43baaf-6ab5-4925-a0c1-ddc793ca773f.png)

1.  如果是这种情况，要加载自定义 PDB 符号，请导航到调试 > 窗口 > 模块，找到`VotingApplication.dll`程序集，右键单击，然后选择“加载符号”，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/d43f60c1-ee89-4bf6-bb04-ad9bd99dd386.png)

1.  导航到您复制了`VotingApplication.pdb`文件的目录。符号将自动加载，断点将变得可触发。

1.  在 Web 浏览器中，执行应该触发断点的操作。

1.  现在，根据您的连接速度，Visual Studio 可能会在调试器完全附加之前冻结一段时间（甚至几分钟）。但是，经过这一最初的小问题后，调试体验应该是令人满意的，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/21f54b4c-d886-45ed-850a-a8cf42c10cb5.png)

恭喜——您已成功远程附加调试器到运行在 Kubernetes Pod 内的进程！

# 总结

在本章中，您已经学会了如何将 ASP.NET MVC 应用程序部署到 Kubernetes 集群，以及如何将容器化的 Microsoft SQL Server 2019 部署到其中。我们展示了如何使现有的.NET Framework 应用程序适合云环境，以及如何为这些应用程序创建健壮的 Dockerfile。接下来，我们为我们的投票应用程序准备了一个 AKS Engine 集群部署，并以单节点故障转移模式部署了由 Azure Disk 支持的 Microsoft SQL Server 2019。该应用程序是使用 Kubernetes 部署部署到集群中的，并且我们使用了 Kubernetes Job 来应用 EF 数据库迁移。之后，您将了解有关扩展 Kubernetes 部署和计算资源超额分配的更多信息。最后，您将深入了解如何通过`kubectl`端口转发使用 Visual Studio 2019 的远程调试器来调试在 Kubernetes Pod 中运行的.NET Framework 应用程序。

下一章将重点介绍更高级的 Kubernetes 功能-我们将扩展我们的投票应用程序，充分利用 Kubernetes 的功能。

# 问题

1.  在 Kubernetes Pod 中运行应用程序注入配置的可能方式有哪些？

1.  微软提供的 Windows 容器日志监视器的目的是什么？

1.  为什么对于复制的应用程序迁移数据库架构是一项具有挑战性的任务？

1.  为什么我们要使用由 Azure Disk 支持的持久卷来存储 Microsoft SQL Server 数据？

1.  如何将 EF 数据库迁移应用到在 Kubernetes 中运行的应用程序？

1.  Kubernetes 中的 CPU/内存资源超额分配是什么？

1.  为什么您需要使用`kubectl`端口转发才能连接到容器中的 Visual Studio 远程调试器？

您可以在本书的*评估*部分找到这些问题的答案。

# 进一步阅读

+   有关 Kubernetes 应用程序管理的更多信息，请参考以下 Packt 图书：

+   *完整的 Kubernetes 指南* ([`www.packtpub.com/virtualization-and-cloud/complete-kubernetes-guide`](https://www.packtpub.com/virtualization-and-cloud/complete-kubernetes-guide)).

+   *开始使用 Kubernetes-第三版* ([`www.packtpub.com/virtualization-and-cloud/getting-started-kubernetes-third-edition`](https://www.packtpub.com/virtualization-and-cloud/getting-started-kubernetes-third-edition)).

+   *面向开发人员的 Kubernetes* ([`www.packtpub.com/virtualization-and-cloud/kubernetes-developers`](https://www.packtpub.com/virtualization-and-cloud/kubernetes-developers)).

+   对于在 Kubernetes 集群中运行的应用程序的替代调试方法（例如 Telepresence），您可以阅读以下文章：

+   [`kubernetes.io/docs/tasks/debug-application-cluster/local-debugging/`](https://kubernetes.io/docs/tasks/debug-application-cluster/local-debugging/).

+   [`www.telepresence.io/tutorials/kubernetes`](https://www.telepresence.io/tutorials/kubernetes).


# 第十一章：配置应用程序以使用 Kubernetes 功能

上一章演示了如何在 Kubernetes 中处理容器化的 Windows 应用程序-现在，我们将扩展我们的投票应用程序，以使用更先进的功能，使编排更加健壮和自动化。多年来，Kubernetes 已经扩展了越来越多的功能，从细粒度的基于角色的访问控制（RBAC）或 Secrets 管理到使用水平 Pod 自动缩放器（HPA）进行自动缩放，这是容器编排的圣杯。当然，我们无法在本书的范围内涵盖所有这些功能，但我们将包括一些最有用的功能，以帮助运行容器化的 Windows 应用程序。另外，请记住，当您运行本地 Kubernetes 集群时，一些功能是不可用的，例如特定于云的 StorageClass 提供程序-我们将要呈现的所有示例都假定您正在运行 AKS Engine Kubernetes 集群。

在本章中，我们将涵盖以下主题：

+   使用命名空间隔离应用程序

+   使用活动探针和就绪探针进行健康监控

+   指定资源限制和配置自动缩放

+   使用 ConfigMaps 和 Secrets 管理应用程序配置

+   在 Windows 节点上管理持久数据存储

+   为部署配置滚动更新

+   RBAC

# 技术要求

在本章中，您将需要以下内容：

+   安装了 Windows 10 Pro、企业版或教育版（1903 版或更高版本，64 位）

+   Microsoft Visual Studio 2019 Community（或任何其他版本），如果您想编辑应用程序的源代码并对其进行调试-Visual Studio Code 对经典.NET Framework 的支持有限

+   一个 Azure 帐户

+   使用 AKS Engine 部署的 Windows/Linux Kubernetes 集群，准备部署上一章的投票应用程序

要跟着做，您需要自己的 Azure 帐户来为 Kubernetes 集群创建 Azure 资源。如果您之前还没有为前几章创建帐户，您可以阅读有关如何获取个人使用的有限免费帐户的更多信息[`azure.microsoft.com/en-us/free/`](https://azure.microsoft.com/en-us/free/)。

使用 AKS Engine 部署 Kubernetes 集群已在第八章中进行了介绍，*部署混合 Azure Kubernetes 服务引擎集群*。将投票应用程序部署到 Kubernetes 已在第十章中进行了介绍，*部署 Microsoft SQL Server 2019 和 ASP.NET MVC 应用程序*。

您可以从官方 GitHub 存储库下载本章的最新代码示例，网址为[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/tree/master/Chapter11`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/tree/master/Chapter11)。

# 使用命名空间隔离应用程序

在上一章中，我们已经使用了一个命名空间（名为`dev`）来将应用程序的组件逻辑地分组到现有物理 Kubernetes 集群中的虚拟集群中。命名空间的一般原则是提供资源配额和对象名称的范围——给定命名空间内的名称必须是唯一的，但它们不必在不同的命名空间中是唯一的。默认情况下，Kubernetes 提供以下开箱即用的命名空间：

+   `kube-system`：由 Kubernetes 系统创建的对象的命名空间，例如`kube-apiserver`或`kube-proxy` Pods。

+   `kube-public`：一个可以被所有用户阅读的命名空间，也不需要经过身份验证——它将在由 kubeadm 引导的集群中创建，并且通常用于系统使用。

+   `default`：没有其他命名空间的对象的命名空间。

根据您的需求和团队的规模，您可能更愿意仅使用对象标签（小团队）或在命名空间级别分隔对象（大团队）：

+   对于小团队，其中单个开发人员能够理解整个系统（大约 10 个微服务），并且整个开发环境可以使用本地集群（如在 VM 上运行的 minikube 或 kubeadm 部署）进行托管，可以仅使用默认命名空间来部署生产服务。或者，您可以为生产工作负载使用专用命名空间，并为开发/分段环境使用单独的命名空间。

+   对于快速增长的中等规模团队，在这种团队中，单个开发人员不在整个系统范围内工作，为每个子团队提供专用的命名空间可能更容易，特别是如果在本地 Kubernetes 集群上无法创建整个开发环境。

+   对于大型团队，子团队几乎独立运作，为每个团队单独创建生产和开发命名空间可能是一个好主意。您还可以考虑为每个命名空间使用资源配额和使用 RBAC。

+   对于企业组织来说，个别团队甚至可能不知道其他团队的存在，创建单独的集群可能比使用命名空间来划分单个集群更容易。这样可以更轻松地管理资源和计费，并在出现问题时提供更好的部署边界。

在创建服务对象时，命名空间会影响服务的**完全限定域名**（**FQDN**）。FQDN 的形式为`<service-name>.<namespace-name>.svc.cluster.local`—这意味着如果您在 Pod 中调用服务时使用`<service-name>`，调用将被限定在此 Pod 所在的命名空间。请注意，跨命名空间调用服务是可能的，但您需要指定 FQDN。

让我们演示如何为您的对象创建一个命名空间。

# 创建命名空间

要创建一个名为`prod`的命名空间，您可以使用以下命令：

```
kubectl create namespace prod
```

与其他对象一样，通常建议使用声明性对象配置管理，并将清单文件应用到 Kubernetes 集群。以下的`namespace-prod.yaml`清单文件将创建`prod`命名空间，另外指定了`ResourceQuota`对象，用于确定此命名空间的总 CPU 和内存配额：

```
---
kind: Namespace
apiVersion: v1
metadata:
  name: prod
  labels:
    name: prod
---
apiVersion: v1
kind: ResourceQuota
metadata:
  namespace: prod
  name: default-resource-quota
spec:
  hard:
    requests.cpu: 500m
    requests.memory: 1Gi
    limits.cpu: "1"
    limits.memory: 2Gi
```

要应用清单文件，请执行以下命令：

```
kubectl apply -f .\namespace-prod.yaml
```

然后，您可以使用`kubectl describe`命令来检查我们的命名空间中使用了多少资源。

```
PS C:\src> kubectl describe resourcequota -n prod
Name:            default-resource-quota
Namespace:       prod
Resource         Used  Hard
--------         ----  ----
limits.cpu       0     1
limits.memory    0     2Gi
requests.cpu     0     500m
requests.memory  0     1Gi
```

Kubernetes 中的资源配额是高度可定制的，可以应用于不同的资源，并使用复杂的选择器进行范围限定。您可以在官方文档中了解更多信息：[`kubernetes.io/docs/concepts/policy/resource-quotas/`](https://kubernetes.io/docs/concepts/policy/resource-quotas/)。

现在，您已经知道如何管理命名空间，让我们看看如何使用`kubectl`命令有效地使用它们。

# kubectl 命令和命名空间

`kubectl`命令按照惯例操作命名空间范围的对象，使用`--namespace`或`-n`标志来指定应用于命令的命名空间。如果您需要查询所有命名空间中的对象，可以使用`--all-namespaces`标志。例如，要列出`prod`命名空间中的所有 Pods，请使用以下命令：

```
kubectl get pods -n prod
```

在之前的章节中，您经常使用了这个构造。但是，值得知道的是，如果命令没有提供命名空间，它将使用当前 kubeconfig 上下文中设置为默认的命名空间。换句话说，它不一定是默认的命名空间 - 这完全取决于您的上下文设置。我们在第六章中深入讨论了上下文，*与 Kubernetes 集群交互* - 为了完整起见，我们将展示如何更改当前上下文中使用的命名空间。要在当前上下文中永久设置`prod`命名空间，请使用以下命令：

```
kubectl config set-context --current --namespace=prod
```

现在，任何支持指定命名空间的命令将默认使用`prod`命名空间。

# 删除命名空间

与其他对象类似，建议以命令方式删除命名空间。要删除`prod`命名空间，请执行以下命令：

```
kubectl delete namespace prod
```

请注意，此命令将删除此命名空间中的所有对象，这意味着这是一个极具破坏性的命令，应谨慎使用！

在下一节中，我们将看到如何使用探针配置容器监视活动性和就绪性。

# 使用活动性和就绪性探针进行健康监控

在 Kubernetes 中，探针由 kubelet 用于确定 Pod 的状态 - 您可以使用它们来自定义如何检查 Pod 是否准备好为您的流量提供服务，或者容器是否需要重新启动。您可以为在 Pod 中运行的每个容器配置三种类型的探针：

+   **就绪探针**：用于确定给定容器是否准备好接受流量。只有当 Pod 的所有容器都准备就绪时，Pod 才被视为准备就绪。不准备就绪的 Pod 将从服务端点中删除，直到它们再次准备就绪为止。

+   **活动性探针**：用于检测容器是否需要重新启动。这可以帮助解决容器陷入死锁或其他问题的情况，当容器进程处于活动状态但无法正常运行时。重新启动容器可能会增加该情况下 Pod 的可用性。

+   **启动探针**：这是用于确定容器是否已完全启动的附加探针-在此探针成功返回之前，就绪和存活探针都是禁用的。这对于由于某些初始化而具有长启动时间的容器特别有用。通过这种方式，您可以避免存活探针的过早终止。

默认情况下，Pod 容器上没有配置探针。但是，只有在 Pod 容器已启动（在 Docker 意义上）并且重新启动容器（当然取决于您的重新启动策略）后，Kubernetes 才会提供流量。

所有类型的探针都可以使用三种类型的处理程序操作进行配置：

+   运行命令（`exec`）-如果容器中运行的给定命令返回非零退出代码，则探针处于失败状态。

+   执行 HTTP GET 请求（`httpGet`）-只有当容器对 HTTP GET 请求做出大于或等于 200 且小于 400 的 HTTP 代码响应时，探针才处于成功状态。

+   在指定端口向容器打开 TCP 套接字（`tcpSocket`）-如果可以建立连接，则探针处于成功状态。

您还应考虑使用终止优雅期限来正确管理 Pod 的容器化应用程序生命周期，并在接收到 SIGTERM 信号时使应用程序优雅地退出（[`cloud.google.com/blog/products/gcp/kubernetes-best-practices-terminating-with-grace`](https://cloud.google.com/blog/products/gcp/kubernetes-best-practices-terminating-with-grace)）。请注意，对于 Windows Pod，截止优雅期限在 Kubernetes 1.17 版本中不受支持。

在处理具有许多依赖组件的大型分布式系统时，使用探针时存在一些注意事项和最佳实践。我们将在解释每种类型的探针时详细介绍细节-反映示例的投票应用程序源代码可以在官方 GitHub 存储库中找到，网址为[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/tree/master/Chapter11/02_voting-application-probes-src`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/tree/master/Chapter11/02_voting-application-probes-src)。首先，让我们看一下最受欢迎的探针，即就绪探针。

# 就绪探针

在 Kubernetes 中使用就绪探针来确定 Pod 容器是否准备好接受来自 Kubernetes 服务的流量——不准备好的 Pod（只有所有容器都被认为准备好的 Pod 才算准备好）将从服务端点列表中删除，直到它们再次准备好。换句话说，这是一个通知给定 Pod 可以用于服务请求的信号。

就就绪探针而言，有一些已经建立的最佳实践是您应该考虑的：

+   只要您的容器可能无法在容器启动后立即准备好为流量提供适当的服务，就使用此探针。

+   确保在就绪探针评估期间检查缓存预热或数据库迁移状态。您还可以考虑在尚未启动的情况下启动预热的实际过程，但要谨慎使用——就绪探针将在 Pod 的生命周期中不断执行，这意味着您不应该为每个请求执行任何昂贵的操作。或者，您可能希望为此目的使用在 Kubernetes 1.16 中新引入的启动探针。

+   对于暴露 HTTP 端点的微服务应用程序，考虑始终配置 `httpGet` 就绪探针。这将确保在容器成功运行但 HTTP 服务器尚未完全初始化时，所有情况都得到覆盖。

+   在应用程序中为就绪检查使用一个单独的专用 HTTP 端点是一个好主意，例如，一个常见的约定是使用 `/health`。

+   如果您在此类探针中检查依赖项（外部数据库和日志记录服务）的状态，请注意共享依赖项，例如投票应用程序中的 SQL Server。在这种情况下，您应该考虑使用探针超时，该超时大于外部依赖项的最大允许超时时间，否则可能会出现级联故障，可用性降低，而不是偶尔增加的延迟。

对于使用 IIS（Internet Information Services 的缩写）托管的 Web 应用程序，就绪探针非常有意义——IIS 应用程序池需要完全启动，数据库迁移可能尚未应用。例如，我们将为我们的投票应用程序配置一个简单的就绪探针，如下所示：

+   ASP.NET MVC 应用程序将实现一个专用控制器，用于提供 `/health` 请求。

+   将检查未决的数据库迁移。请注意，这将间接验证数据库连接状态，这在某些情况下可能是不可取的。因此，我们将使用大于 30 秒的探针超时（默认的 SQL 命令超时）。

+   控制器操作将返回一个简单的 JSON。在检查失败的情况下，HTTP 状态将为 503，在成功的情况下为 200。

要为投票应用程序添加就绪探针，请按照以下步骤进行：

1.  健康检查控制器操作的实现可以在`HealthController`类中找到（[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter11/02_voting-application-probes-src/Controllers/HealthController.cs`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter11/02_voting-application-probes-src/Controllers/HealthController.cs)），如下所示：

```
public ActionResult CheckHealth()
{
    this.Response.TrySkipIisCustomErrors = true;

    if (!this.db.Database.CompatibleWithModel(throwIfNoMetadata: true))
    {
        this.Response.StatusCode = (int)HttpStatusCode.ServiceUnavailable;
        return this.Json(new { status = "Database migrations pending" }, JsonRequestBehavior.AllowGet);
    }

    return this.Json(new { status = "Ok" }, JsonRequestBehavior.AllowGet);
}
```

1.  另外，您需要记住在`RouteConfig`类（[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter11/02_voting-application-probes-src/App_Start/RouteConfig.cs`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter11/02_voting-application-probes-src/App_Start/RouteConfig.cs)）中修改应用程序的路由配置，然后是默认路由映射。

```
routes.MapRoute(
    name: "Health",
    url: "health",
    defaults: new { controller = "Health", action = "CheckHealth" });
```

1.  与上一章一样，构建应用程序的 Docker 镜像，将其标记为 1.1.0 版本，并将其推送到 Docker Hub。在我们的演示案例中，我们将使用`packtpubkubernetesonwindows/voting-application:1.1.0`镜像。

1.  修改部署清单文件`voting-application.yaml`，以包括`frontend`容器的以下就绪探针配置：

```
apiVersion: apps/v1
kind: Deployment
metadata:
  namespace: dev
  name: voting-application-frontend
  ...
spec:
  ...
  template:
    ...
    spec:
      ...
      containers:
      - name: frontend
        image: packtpubkubernetesonwindows/voting-application:1.1.0
        ...
        readinessProbe:
          httpGet:
            path: /health
            port: 80
          initialDelaySeconds: 30
          periodSeconds: 10
          timeoutSeconds: 40
          successThreshold: 1
          failureThreshold: 3
        ...
```

探针被配置为调用`/health`端点，这将执行我们之前实现的控制器操作。探针配置中的重要部分如下：

+   +   将`initialDelaySeconds`设置为`30`秒，以允许 IIS 完全初始化。原来，对在`ServiceMonitor.exe`监督下运行的应用程序进行过早调用可能会导致容器过早退出（也许是`ServiceMonitor.exe`实现中的一个错误）。

+   `timeoutSeconds`设置为`40`秒，以超过默认设置为`30`秒的 SQL Server 数据库超时。

1.  现在，使用`kubectl apply -f .\voting-application-readiness-probe.yaml`命令应用清单文件。

1.  像往常一样，使用`kubectl get pods -n dev`和`kubectl describe`命令来检查部署过程。在 Pod 事件中，你可以验证 Pod 是否有任何就绪失败。

1.  在 Web 浏览器中，当你导航到应用程序时，你不应该遇到任何 IIS 应用程序池启动延迟——Web 服务器将通过就绪检查进行预热。

现在，让我们来看看另一个确定 Pod 容器存活状态的探针。

# 存活探针

第二种探针是存活探针，它可以在清单中类似于就绪探针进行配置。存活探针用于确定是否需要重新启动 Pod 容器。当进程尚未退出但无法处理任何操作时，这种类型的探针可能对恢复死锁或其他类型的容器问题有用。

与就绪探针类似，关于何时以及如何使用存活探针，有一些指导方针。

+   存活探针应该谨慎使用。错误的配置可能导致服务和容器重启循环中的级联故障。作为一个快速实验，你可以重新部署投票应用程序清单，其中用存活探针替换就绪探针，配置类似但超短的超时和延迟——你将遇到多次随机崩溃和应用程序的可用性不佳！

+   除非你有充分的理由，否则不要使用活跃探针。一个充分的理由可能是你的应用程序中存在一个已知的死锁问题，但尚未找到根本原因。

+   执行简单快速的检查来确定进程的状态，而不是它的依赖关系。换句话说，在存活探针中不要检查外部依赖的状态——这可能会导致由于大量容器重启而产生级联故障，并且会过载一小部分服务 Pod。

+   如果你的容器中运行的进程能够在遇到无法恢复的错误时崩溃或退出，那么你可能根本不需要存活探针。

+   使用保守的`initialDelaySeconds`设置，以避免任何过早的容器重启并陷入重启循环。

如果您不确定`ServiceMonitor.exe`和`LogMonitor.exe`入口进程的内部情况，那么由 IIS 托管的 Web 应用程序可能是使用活动探针的一个很好的选择。理论上，它们应该在 IIS 或 IIS 应用程序池出现问题时使容器崩溃，但让我们假设我们需要自己实现这些检查。我们将实现一个活动探针，它将使用`exec`处理程序检查 IIS 应用程序池是否正在运行。为此，请按照以下步骤进行操作：

1.  使用`Deployment`为我们的应用程序修改`voting-application.yaml`清单文件。为`frontend`容器添加以下活动探针配置：

```
apiVersion: apps/v1
kind: Deployment
metadata:
  namespace: dev
  name: voting-application-frontend
  ...
spec:
  ...
  template:
    ...
    spec:
    ...
    containers:
    - name: frontend
    image: packtpubkubernetesonwindows/voting-application:1.1.0
    ...
    livenessProbe:
      exec:
        command:
        - powershell.exe
        - -Command
        - if ((Get-WebAppPoolState DefaultAppPool).Value -ne "Started") { throw "Default IIS App Pool is NOT started" }
        initialDelaySeconds: 45
        periodSeconds: 10
        timeoutSeconds: 10
        successThreshold: 1
        failureThreshold: 3
        ...
```

探针被配置为执行 PowerShell 命令，`if ((Get-WebAppPoolState DefaultAppPool).Value -ne "Started") { throw "Default IIS App Pool is NOT started" }`，该命令检查默认的 IIS 应用程序池是否处于`Started`状态。如果不是，则将抛出异常，并且 PowerShell 进程将以非零退出代码退出，导致探针进入失败状态。

1.  现在，使用`kubectl apply -f .\voting-application-readiness-probe.yaml`命令应用清单文件。

1.  再次使用`kubectl get pods -n dev`和`kubectl describe`命令检查滚动升级过程。在 Pod 事件中，您可以验证 Pod 是否有任何活动失败。

在使用`exec`处理程序时，您应该仔细分析所选命令的行为。据报道，`exec`处理程序在某些情况下会导致僵尸进程膨胀。

最后，让我们快速看一下最后一种类型的探针，即启动探针。

# 启动探针

最近在 Kubernetes 1.16 中引入了启动探针，以支持容器可能需要比设置在就绪探针中的`initialDelaySeconds + failureThreshold * periodSeconds`更多时间进行初始化的情况。通常情况下，您应该为启动探针使用与就绪探针相同的处理程序配置，但使用更长的延迟。如果容器在`initialDelaySeconds + failureThreshold * periodSeconds`内未准备好进行就绪探针，则容器将被终止，并受到 Pod 的重启策略的影响。

我们的投票应用程序不需要专门的启动探针，但在部署清单文件中的示例定义可能如下所示：

```
apiVersion: apps/v1
kind: Deployment
metadata:
  namespace: dev
  name: voting-application-frontend
  ...
spec:
  ...
  template:
    ...
    spec:
      ...
      containers:
      - name: frontend
        image: packtpubkubernetesonwindows/voting-application:1.1.0
        ...
        startupProbe:
          httpGet:
            path: /health
            port: 80
          initialDelaySeconds: 30
          periodSeconds: 60
          timeoutSeconds: 40
          successThreshold: 1
          failureThreshold: 5
        ...
```

在下一节中，我们将专注于为 Pod 分配资源限制以及如何为我们的投票应用程序配置自动缩放。

# 指定资源限制和配置自动缩放

作为容器编排器，Kubernetes 默认提供了两个重要功能，帮助管理您的集群资源：

+   Pod 容器的资源请求和限制

+   HPA，它允许根据 CPU 资源使用情况（稳定支持）、内存资源使用情况（beta 支持）或自定义指标（也是 beta 支持）自动扩展您的部署或有状态集

让我们首先看一下指定资源请求和限制。

# 资源请求和限制

当您创建一个 Pod 时，可以指定其容器需要多少计算资源 - 我们已经在上一章中对投票应用程序分配资源进行了简短的练习。一般来说，计算资源是 CPU 和 RAM 内存 - Kubernetes 还能够管理其他资源，例如 Linux 上的 HugePages 或本地节点上的临时存储。

Kubernetes 资源模型提供了两类资源之间的额外区分：可压缩和不可压缩。简而言之，可压缩资源可以轻松进行限流，而不会造成严重后果。这样的资源的一个完美例子是 CPU - 如果您需要限制给定容器的 CPU 使用率，容器将正常运行，只是速度较慢。另一方面，我们有不可压缩资源，如果不加限制会造成严重后果 - 内存分配就是这样一个资源的例子。

有两份很棒的设计提案文件描述了 Kubernetes 资源模型（[`github.com/kubernetes/community/blob/master/contributors/design-proposals/scheduling/resources.md`](https://github.com/kubernetes/community/blob/master/contributors/design-proposals/scheduling/resources.md)）和资源服务质量（[`github.com/kubernetes/community/blob/master/contributors/design-proposals/node/resource-qos.md`](https://github.com/kubernetes/community/blob/master/contributors/design-proposals/node/resource-qos.md)）。我们强烈建议阅读它们，以充分了解 Kubernetes 资源管理的愿景以及已经实现的功能。

您可以为 Pod 容器指定两个值，关于资源分配：

+   `requests`：这指定了系统提供的特定资源的保证数量。你也可以反过来想，这是 Pod 容器从系统中需要的特定资源的数量，以便正常运行。Pod 的调度取决于`requests`值（而不是`limits`）。

+   `limits`：这指定了系统提供的特定资源的最大数量。如果与`requests`一起指定，这个值必须大于或等于`requests`。根据资源是可压缩还是不可压缩，超出限制会产生不同的后果——可压缩资源（CPU）将被限制，而不可压缩资源（内存）可能会导致容器被杀死。

使用不同的`requests`和`limits`值允许资源超额分配，这对于有效处理资源使用的短暂突发情况并在平均情况下更好地利用资源是有用的。如果根本不指定限制，容器可以在节点上消耗任意数量的资源。这可以通过命名空间资源配额（本章前面介绍的）和限制范围来控制——你可以在文档中阅读更多关于这些对象的信息[`kubernetes.io/docs/concepts/policy/limit-range/`](https://kubernetes.io/docs/concepts/policy/limit-range/)。

我们在 Kubernetes 中的 Windows 节点上涵盖了资源管理支持的详细信息，详见第四章，*Kubernetes 概念和 Windows 支持*。重要的是，Windows 目前缺乏对内存杀手的支持（Kubernetes 中即将推出的 Hyper-V 容器功能可能会提供一些内存限制的支持）。这意味着超出 Windows 容器内存的`limits`值不会导致任何限制或容器重启。在这里，经验法则是仔细使用`requests`来管理内存调度，并监视任何突然的内存分页。

在深入配置细节之前，我们需要了解 Kubernetes 中用于测量 CPU 资源和内存的单位是什么。对于 CPU 资源，基本单位是**Kubernetes CPU**（**KCU**），其中`1`等同于例如 Azure 上的 1 个 vCPU，GCP 上的 1 个 Core，或者裸机上的 1 个超线程核心。允许使用小数值：`0.1`也可以指定为`100m`（毫 CPU）。对于内存，基本单位是字节；当然，您可以指定标准单位前缀，如`M`，`Mi`，`G`或`Gi`。

为了演示如何使用资源`limits`和`requests`，请按照以下步骤操作：

1.  修改`voting-application.yaml`部署配置，使其不指定任何更新`strategy`，并为 CPU 和内存设置资源分配：

```
apiVersion: apps/v1
kind: Deployment
metadata:
  namespace: dev
  name: voting-application-frontend
  ...
spec:
  replicas: 5
  ...
  # strategy:
  ...
  template:
    ...
    spec:
      ...
      containers:
      - name: frontend
        ...        
        resources:
          limits:
            cpu: 1000m
          requests:
            cpu: 1000m
            memory: 256Mi
```

对于内存，我们遵循 Windows 节点的当前建议——我们只指定了想要请求多少内存。为了模拟资源耗尽，我们指定了一个大的请求值，将消耗 Windows 节点的所有集群 CPU。这是因为两个具有 Azure VM 类型 Standard_D2_v3 的节点每个都有两个 vCPU，并且运行五个副本，我们总共需要五个 vCPU。需要删除更新`strategy`以避免在部署过程中出现任何死锁。

1.  使用`kubectl apply -f .\voting-application.yaml`命令应用配置文件。

1.  现在，仔细观察您的部署中新 Pod 的创建。您会注意到有一些 Pod 显示`Pending`状态：

```
PS C:\src> kubectl get pods -n dev
NAME                                            READY   STATUS      RESTARTS   AGE
voting-application-frontend-54bbbbd655-nzt2n    1/1     Running     0          118s
voting-application-frontend-54bbbbd655-phdhr    0/1     Pending     0          118s
voting-application-frontend-54bbbbd655-qggc2    1/1     Running     0          118s
...
```

1.  这是预期的，因为`voting-application-frontend-54bbbbd655-phdhr` Pod 无法被调度到任何节点，因为没有可用的 CPU 资源。要检查实际原因，描述 Pod 并检查 `Events`：

```
PS C:\src> kubectl describe pod -n dev voting-application-frontend-54bbbbd655-phdhr
Events:
 Type     Reason            Age        From                 Message
 ----     ------            ----       ----                 -------
 Warning  FailedScheduling  <unknown>  default-scheduler    0/5 nodes are available: 2 Insufficient cpu, 3 node(s) didn't match node selector.
```

1.  正如预期的那样，由于所有匹配节点选择器的节点上都没有足够的 CPU 资源，Pod 无法被调度。让我们通过降低 Pod 容器的 `requests` 和 `limits` CPU 值来解决这个问题——修改 `voting-application.yaml` 配置文件，使 `requests` 设置为 `250m`，`limits` 设置为 `500m`。

1.  使用`kubectl apply -f .\voting-application.yaml`命令应用配置文件，并观察成功的部署。

现在您知道如何为您的容器分配和管理资源，我们可以演示如何使用 HPA 对您的应用程序进行自动缩放。

# HPA

Kubernetes 的真正力量在于 HPA 实现的自动扩展，它是由`HorizontalPodAutoscaler` API 对象支持的专用控制器。在高层次上，HPA 的目标是根据当前 CPU 利用率或其他自定义指标（包括同时使用多个指标）自动扩展部署或 StatefulSet 中副本的数量。根据指标值确定目标副本数量的算法的详细信息可以在[`kubernetes.io/docs/tasks/run-application/horizontal-Pod-autoscale/#algorithm-details`](https://kubernetes.io/docs/tasks/run-application/horizontal-pod-autoscale/#algorithm-details)找到。HPA 是高度可配置的，在本书中，我们将介绍基于目标 CPU 使用率自动扩展的标准场景。

我们的投票应用程序公开了不需要太多 CPU 的功能，这意味着可能很难按需触发自动扩展。为了解决这个问题，我们将添加一个专用的控制器动作，可以模拟具有给定目标百分比值的恒定 CPU 负载。用于压力模拟的`packtpubkubernetesonwindows/voting-application:1.2.0` Docker 镜像的源代码可以在[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/tree/master/Chapter11/08_voting-application-hpa-src`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/tree/master/Chapter11/08_voting-application-hpa-src)找到。如果您想自定义应用程序，请在 Visual Studio 2019 中打开您的解决方案，并按照以下步骤操作：

1.  定义`StressCpuWorker`类（[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter11/08_voting-application-hpa-src/Services/CpuStressWorker.cs`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter11/08_voting-application-hpa-src/Services/CpuStressWorker.cs)），其中包含用于模拟 CPU 压力的主要工作代码：

```
private void StartCpuStress()
{
    this.logger.Info($"Environment.ProcessorCount: {Environment.ProcessorCount}");

    for (int i = 0; i < Environment.ProcessorCount; i++)
    {
        var thread = new Thread(
            () =>
                {
                    var watch = new Stopwatch();
                    watch.Start();

                    while (this.isEnabled)
                    {
                        if (watch.ElapsedMilliseconds <= this.targetCpuLoad)
                        {
                            continue;
                        }

                        Thread.Sleep(100 - this.targetCpuLoad);

                        watch.Reset();
                        watch.Start();
                    }
                });

        thread.Start();
    }
}
```

此代码将启动多个线程，数量将等于环境中当前可用的处理器数量，然后通过几乎空的`while`循环来对每个逻辑处理器进行`this.targetCpuLoad`毫秒的压力测试。在剩余的 100 毫秒“段”中，线程将进入睡眠状态——这意味着平均而言，我们应该将所有可用的 CPU 负载到`this.targetCpuLoad`百分比。当然，这取决于分配给容器的处理器数量——这个数字可能会根据您的`requests`和`limits`值而变化；您可以随时检查 Pod 日志，以查看此 Pod 可用的逻辑处理器数量。另请注意，即使容器有两个逻辑处理器可用，也不意味着容器能够充分利用它们；负载可能会受到`limits`值的限制。

1.  在`HomeController`类中（[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter11/08_voting-application-hpa-src/Controllers/HomeController.cs`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter11/08_voting-application-hpa-src/Controllers/HomeController.cs)），添加一个新的控制器操作，可以通过`/Home/StressCpu?value={targetPercent}`路由访问。请注意，我们允许通过 GET 请求（而不是 PUT）执行此操作，以便在使用 Web 浏览器时交互更加简单。此外，将`IStressCpuWorker`注入到构造函数中——最终操作实现如下：

```
public ActionResult StressCpu([FromUri] int value)
{
    this.Response.StatusCode = (int)HttpStatusCode.Accepted;
    var host = Dns.GetHostEntry(string.Empty).HostName;

    if (value < 0)
    {
        this.cpuStressWorker.Disable();
        return this.Json(new { host, status = $"Stressing CPU turned off" }, JsonRequestBehavior.AllowGet);
    }

    if (value > 100)
    {
        value = 100;
    }

    this.cpuStressWorker.Enable(value);
    return this.Json(new { host, status = $"Stressing CPU at {value}% level" }, JsonRequestBehavior.AllowGet);
}
```

如果提供正值，此实现将启用 CPU 压力测试；如果提供负值，将禁用压力测试。

1.  在`NinjectWebCommon`类中配置依赖注入（[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter11/08_voting-application-hpa-src/App_Start/NinjectWebCommon.cs`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter11/08_voting-application-hpa-src/App_Start/NinjectWebCommon.cs)）。确保`StressCpuWorker`类被解析为单例：

```
kernel.Bind<ICpuStressWorker>().To<CpuStressWorker>().InSingletonScope();
```

1.  使用标签`1.2.0`构建 Docker 镜像，并将其推送到您的存储库，就像我们之前做的那样。

准备好镜像后，我们可以继续部署投票应用的新版本并配置自动缩放。为此，请执行以下步骤：

1.  修改`voting-application.yaml`清单文件，并确保您使用图像的`1.2.0`标记，并且`resources`指定如下：

```
resources:
  limits:
    cpu: 500m
  requests:
    cpu: 400m
    memory: 256Mi
```

1.  在 PowerShell 窗口中，使用`kubectl apply -f .\voting-application.yaml`命令应用清单文件。

1.  等待部署完成，并使用此命令观察 Pod 的 CPU 使用情况：

```
PS C:\src> kubectl top pod -n dev
NAME                                           CPU(cores)   MEMORY(bytes)
mssql-deployment-58bcb8b89d-7f9xz              339m         903Mi
voting-application-frontend-6b6c9557f8-5wwln   117m         150Mi
voting-application-frontend-6b6c9557f8-f787m   221m         148Mi
voting-application-frontend-6b6c9557f8-rjwmj   144m         164Mi
voting-application-frontend-6b6c9557f8-txwl2   120m         191Mi
voting-application-frontend-6b6c9557f8-vw5r9   160m         151Mi
```

当 IIS 应用程序池完全初始化时，每个 Pod 的 CPU 使用率应稳定在`150m`左右。

1.  为 HPA 创建`hpa.yaml`清单文件：

```
apiVersion: autoscaling/v1
kind: HorizontalPodAutoscaler
metadata:
  namespace: dev
  name: voting-application-frontend
spec:
  minReplicas: 1
  maxReplicas: 8
  targetCPUUtilizationPercentage: 60
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: voting-application-frontend
```

此 HPA 将自动将`voting-application-frontend`部署扩展到`1`到`8`个副本之间，尝试将 CPU 使用率定位到`60`％。请注意，此目标使用率较高，在生产环境中，您应考虑使用更低、更合适的值。此清单文件与使用`kubectl autoscale deployment/voting-application-frontend -n dev --cpu-percent=60 --min=1 --max=8`命令创建的 HPA 大致相同。

1.  使用`kubectl apply -f .\hpa.yaml`命令应用清单文件。

1.  HPA 受到延迟的影响，以避免频繁波动（即副本计数频繁波动）。默认延迟为五分钟。这意味着在应用后，您应该期望一些延迟，直到 HPA 扩展部署。使用`kubectl describe`命令监视 HPA 的状态：

```
PS C:\src> kubectl describe hpa -n dev voting-application-frontend
...
Metrics:                                               ( current / target )
 resource cpu on pods (as a percentage of request): 37% (150m) / 60%
Events:
 Type     Reason                        Age   From                       Message
 ----     ------                        ----  ----                       -------
...
 Normal   SuccessfulRescale             8m6s  horizontal-Pod-autoscaler  New size: 4; reason: All metrics below target
 Normal   SuccessfulRescale             3m3s  horizontal-Pod-autoscaler  New size: 3; reason: All metrics below targetcpu
```

随着时间的推移，您会注意到 HPA 倾向于缩减到单个副本，因为 CPU 负载不足。

1.  让我们使用我们的专用端点增加 CPU 负载。在 Web 浏览器中，转到以下 URL：`http://<serviceExternalIp>/Home/StressCpu?value=90`。这将开始以 90％的目标水平压力 CPU-请记住，根据 Pod 分配的逻辑处理器的方式，实际使用情况可能会有所不同。

1.  您可以执行多个请求，以确保部署中的更多 Pod 开始对 CPU 施加压力。

1.  过一段时间，观察 HPA 事件中发生了什么：

```
 Normal   SuccessfulRescale             7m44s            horizontal-Pod-autoscaler  New size: 4; reason: cpu resource utilization (percentage of request) above target
 Normal   SuccessfulRescale             7m29s               horizontal-Pod-autoscaler  New size: 5; reason: cpu resource utilization (percentage of request) above target
 Normal   SuccessfulRescale             2m25s               horizontal-Pod-autoscaler  New size: 8; reason: cpu resource utilization (percentage of request) above target
```

由于 CPU 资源利用率超过了 60％的目标，部署会自动扩展！添加更多 Pod 后，平均利用率将下降，因为并非所有 Pod 都在执行 CPU 压力测试。

对于 AKS 和 AKS Engine 集群，可以利用集群自动缩放器根据资源需求自动调整集群中节点的数量。您可以在官方 Azure 文档([`docs.microsoft.com/en-us/azure/aks/cluster-autoscaler`](https://docs.microsoft.com/en-us/azure/aks/cluster-autoscaler))和 Azure 上配置集群自动缩放器的指南中阅读更多信息([`github.com/kubernetes/autoscaler/blob/master/cluster-autoscaler/cloudprovider/azure/README.md`](https://github.com/kubernetes/autoscaler/blob/master/cluster-autoscaler/cloudprovider/azure/README.md))。

恭喜，您已成功为投票应用程序配置了 HPA。我们接下来要演示的 Kubernetes 功能是使用 ConfigMaps 和 Secrets 注入配置数据。

# 使用 ConfigMaps 和 Secrets 管理应用程序配置

为在 Kubernetes 上运行的应用程序提供配置，有几种可能的方法，记录在[`kubernetes.io/docs/tasks/inject-data-application/`](https://kubernetes.io/docs/tasks/inject-data-application/)中：

+   向容器命令传递参数

+   为容器定义系统环境变量

+   将 ConfigMaps 或 Secrets 挂载为容器卷

+   可选地，使用 PodPresets 将所有内容包装起来。

本节将重点介绍使用 ConfigMaps 和 Secrets，它们在许多方面都很相似，但目的却非常不同。

首先，让我们来看看 Secrets。在几乎每个应用程序中，您都必须管理访问依赖项的敏感信息，例如密码、OAuth 令牌或证书。将这些信息作为硬编码值放入 Docker 镜像是不可能的，因为存在明显的安全问题和非常有限的灵活性。同样，直接在 Pod 清单文件中定义密码是不推荐的——清单文件应该保存在源代码控制中，绝对不是存储这种敏感信息的地方。为了管理这种类型的信息，Kubernetes 提供了 Secret 对象，它可以保存技术上任何类型的由键值对组成的数据。可选地，可以在`etcd`中对 Secrets 进行加密，这在生产场景中是推荐的。

现在，我们将演示如何使用`kubectl`创建一个通用（不透明）的 Secret。您也可以使用清单文件来实现这个目的，但是如何生成这些清单文件取决于您的 CI/CD 流水线（您不希望将这些清单文件提交到源代码控制中！）。要为 SQL Server 密码创建一个 Secret，请执行以下步骤：

1.  打开一个 PowerShell 窗口。

1.  假设您想在`dev`命名空间中创建一个名为`mssql`的 Secret，其中`SA_PASSWORD`键下保存着`S3cur3P@ssw0rd`，则执行以下命令：

```
kubectl create secret generic -n dev mssql --from-literal=SA_PASSWORD="S3cur3P@ssw0rd"
```

1.  现在，该 Secret 可以作为容器中的卷（作为文件或目录）来使用，或者用于为容器定义环境变量。对于投票应用程序，更容易使用具有 SQL Server 密码的 Secret 作为环境变量。在部署清单中，可以通过以下方式实现这一点：

```
apiVersion: apps/v1
kind: Deployment
metadata:
  namespace: dev
  name: voting-application-frontend
  ...
spec:
  ...
  template:
    ...
    spec:
      ...
      containers:
      - name: frontend
        image: packtpubkubernetesonwindows/voting-application:1.2.0
        env:
        - name: MSSQL_SA_PASSWORD
          valueFrom:
            secretKeyRef:
              name: mssql
              key: SA_PASSWORD
        - name: CONNECTIONSTRING_VotingApplication
          value: "Data Source=mssql-deployment;Initial Catalog=VotingApplication;MultipleActiveResultSets=true;User Id=sa;Password=$(MSSQL_SA_PASSWORD);"
```

这里的关键概念是使用`secretKeyRef`来引用我们刚刚创建的`mssql` Secret 中`SA_PASSWORD`键的值。该值被注入到`MSSQL_SA_PASSWORD`环境变量中（但是当使用`kubectl describe`时，您无法看到该值！），应用程序在容器中运行时可以访问该值。在我们的情况下，我们使用这个变量来定义另一个环境变量，名为`CONNECTIONSTRING_VotingApplication`。当您需要创建一个包含密码的连接字符串时，这是一个常见的模式，但请记住，这可能比使用卷更不安全。

在使用 Secrets 作为环境变量和作为挂载卷时，有一个重要的区别：通过卷提供的 Secret 数据将在 Secret 更改时进行更新。根据您的需求和实现细节，您可能希望选择将 Secrets 作为卷进行挂载。当然，这要求您的应用程序意识到 Secrets 文件可能发生变化，这意味着它需要积极监视文件系统，并刷新任何凭据提供者、连接字符串或证书，这些通常保存在内存中。将 Secrets 作为不可变的配置值是最佳选择（无论是作为卷挂载还是作为环境变量），这样可以使您的应用程序更可预测，更简单。但是，如果您的架构有限制，希望尽可能少地重新启动 Pod，那么将 Secrets 作为卷进行注入，并在应用程序中实现自动刷新可能是建议的解决方案。

从安全的角度来看，将 Secrets 作为环境变量注入在 Linux 上是不太安全的，因为当具有 root 权限时，您可以从`/proc/<pid>/environ`中枚举出一个进程的所有环境变量。在 Windows 节点上，问题更加复杂：您仍然可以访问进程的环境变量，但卷目前无法使用内存文件系统。这意味着 Secrets 会直接存储在节点的磁盘存储上。

为了存储应用程序的非敏感配置数据，Kubernetes 提供了 ConfigMap 对象。这是另一个概念，您可以使用它来完全解耦 Docker 镜像（构建产物）和运行时配置数据。从 API 的角度来看，这个概念类似于 Secrets——您可以存储键值对，并将它们注入到容器的环境变量中，或者使用卷将它们挂载为文件或目录。为了演示这一点，我们将创建一个 ConfigMap 来存储一个名为`customErrors.config`的配置文件，该文件在 ASP.NET MVC 应用程序的`Web.config`文件中被引用，并使用卷进行挂载。

如第四章中所述，*Kubernetes 概念和 Windows 支持*，截至 Kubernetes 1.17 版本，不支持在 Windows 上将卷`subPath`挂载为文件。这意味着无法轻松地使用 ConfigMap 覆盖整个 ASP.NET MVC 的`Web.config`文件。

请按照以下步骤操作：

1.  首先，我们需要对投票应用程序源代码进行一些小的更改（[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/tree/master/Chapter11/10_voting-application-configmap-src`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/tree/master/Chapter11/10_voting-application-configmap-src)）。我们将从`<system.web>`节点中提取`<customErrors>`节点到一个子目录中的单独文件中。在`Web.config`文件中，将`<system.web>`节点更改为：

```
  <system.web>
    <compilation debug="true" targetFramework="4.8" />
    <httpRuntime targetFramework="4.8" />
    <customErrors configSource="config\customErrors.config" />
  </system.web>
```

1.  在`config`目录中创建`customErrors.config`文件，内容如下。我们将在接下来的步骤中使用 ConfigMap 进行覆盖：

```
<customErrors mode="On" />
```

1.  使用`1.3.0`标签构建一个 Docker 镜像，并将其发布到 Docker Hub，就像之前的示例一样。

1.  创建`voting-application-customerrors-config.yaml`清单文件，用于定义具有以下形式的 ConfigMap，并包含文件（[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter11/10_voting-application-configmap-src/config/customErrors.config`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter11/10_voting-application-configmap-src/config/customErrors.config)）作为`data`：

```
kind: ConfigMap 
apiVersion: v1 
metadata: 
  namespace: dev 
  name: voting-application-customerrors-config
  labels: 
    app: voting-application
data: 
  customErrors.config: |
    <customErrors mode="On" />
```

可以使用`kubectl`命令以命令方式创建 ConfigMaps，但我们想演示 ConfigMap 清单文件的结构。重要的部分是在使用 YAML 多行字符串时保持正确的缩进以适应更大的配置文件（`|`）。

1.  使用`kubectl apply -f .\voting-application-customerrors-config.yaml`命令应用清单文件。

1.  修改`voting-application.yaml`清单文件以在容器中将我们的 ConfigMap 作为目录挂载（记得使用新的 Docker 镜像标签）：

```
apiVersion: apps/v1
kind: Deployment
metadata:
  namespace: dev
  name: voting-application-frontend
  ...
spec:
  ...
  template:
    ...
    spec:
      ...
      containers:
      - name: frontend
        image: packtpubkubernetesonwindows/voting-application:1.3.0
        ...
        volumeMounts:
        - name: customerrors-config-volume
          mountPath: C:\inetpub\wwwroot\config\
        ...
      volumes:
      - name: customerrors-config-volume
        configMap:
          name: voting-application-customerrors-config
```

这里的重要部分是将`voting-application-customerrors-config` ConfigMap 作为卷（`customerrors-config-volume`）引用，并将其挂载到容器中的`C:\inetpub\wwwroot\config\`。如果当前在 Windows 上支持`subPath`挂载，我们可以只覆盖单个文件而不是整个目录。

1.  使用`kubectl apply -f .\voting-application.yaml`命令应用清单文件。

1.  现在，在浏览器中导航到`http://<serviceExternalIp>/Home/StressCpu`地址。这将触发一个异常-我们没有在 URL 中提供所需的请求参数。您应该会看到一个自定义错误页面，只是通知“在处理您的请求时发生错误”。

1.  关闭自定义错误页面，并修改`voting-application-customerrors-config.yaml`清单文件的 ConfigMap，使其包含节点：

```
  customErrors.config: |
    <customErrors mode="Off" />
```

1.  使用`kubectl apply -f .\voting-application-customerrors-config.yaml`命令应用清单文件。

根据 IIS 是否能够监视`C:\inetpub\wwwroot\config\`目录中的更改，IIS 应用程序池可能不会在 Pod 中重新加载。在这种情况下，`exec`进入容器并执行`Restart-WebAppPool DefaultAppPool`命令。

1.  再次导航到`http://<serviceExternalIp>/Home/StressCpu`。如果您的 IIS 应用程序池已重新加载，您将看到完整的异常详细信息，而不是自定义错误页面。

通过这种方式，我们已经演示了如何在 Windows Pods 中使用 Secrets 和 ConfigMaps。现在，是时候熟悉在 Windows 节点上管理持久数据存储了。

# 在 Windows 节点上管理持久数据存储

在第四章 *Kubernetes 概念和 Windows 支持*中，我们已经涵盖了 Kubernetes 中一些与存储相关的概念，如**PersistentVolumes**（**PV**）、**PersistentVolumeClaims**（**PVC**）和**StorageClasses**（**SC**），以及它们在 Windows 工作负载中的支持。在容器化应用程序中管理状态和存储以及使用 StatefulSets 是一个广泛且复杂的主题，不在本书的范围内——官方文档提供了一个很好的介绍，可以在[`kubernetes.io/docs/concepts/storage/`](https://kubernetes.io/docs/concepts/storage/)找到。对于 Windows Pods 的 PersistentVolume 支持的关键要点是，您可以使用一些现有的卷插件，但不是全部。在 Windows 上，支持以下内容：

+   树内卷插件：azureDisk、azureFile、gcePersistentDisk、awsElasticBlockStore（自 1.16 版起）和 vsphereVolume（自 1.16 版起）

+   FlexVolume 插件：SMB 和 iSCSI

+   CSI 卷插件（树外插件）

这意味着，对于 Windows 节点，在 AKS 或 AKS Engine 集群的情况下，您只能使用 azureDisk 和 azureFile in-tree 卷插件，从技术上讲，您可以将 FlexVolume SMB 插件与 Azure Files SMB 共享相结合。对于本地场景，您必须依赖于配置为使用自己的存储或连接到作为外部云服务公开的 SMB 共享的 FlexVolume SMB 或 iSCSI 插件。如果您在 vSphere 上运行，当然可以利用 vsphereVolume 插件。总的来说，在本地运行的混合 Windows/Linux 集群中处理持久卷仍然很困难。

对于本地集群，使用 Rook（[`rook.io/`](https://rook.io/)）来编排存储并与 Kubernetes 集成是一个很好的解决方案。不幸的是，即使是用于消耗卷的 Windows 也没有支持。

我们的投票应用程序已经在 Linux Pod 中运行 SQL Server 时使用了 PersistentVolumes - 在这种情况下，我们一直在使用 StorageClass 与`kubernetes.io/azure-disk`供应程序，它在内部使用 azureDisk 卷插件。这种情况涉及 Linux Pod - 现在，我们将为 Windows Pod 使用 PersistentVolumes。投票应用程序在前端容器中没有特定的数据持久化需求，但作为一个纯粹的例子，我们将展示如何为每个 Pod 存储一个投票日志。

此更改的源代码可在[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/tree/master/Chapter11/12_voting-application-persistentvolume-src`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/tree/master/Chapter11/12_voting-application-persistentvolume-src)上找到。我们不会详细介绍实现细节，但更改很简单：

+   添加一个新的`VoteLogManager`类（[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter11/12_voting-application-persistentvolume-src/Services/VoteLogManager.cs`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter11/12_voting-application-persistentvolume-src/Services/VoteLogManager.cs)），它管理`C:\data\voting.log`文件 - 您可以向日志中添加新的投票并读取日志内容。此日志文件将使用 Kubernetes PersistentVolume 进行持久化。

+   在`SurveyController`类中添加每个投票后，通知`VoteLogManager`。

+   在`HomeController`类中添加一个新的控制器操作`VotingLog`，返回投票日志的内容。然后，您可以使用`http://<serviceExternalIp>/Home/VotingLog`访问当前提供的副本的投票日志。

要部署应用程序，请执行以下步骤：

1.  为投票应用程序构建一个标记为`1.4.0`的 Docker 镜像，并像之前的示例一样将其推送到 Docker Hub。

1.  我们需要将部署转换为 StatefulSet。因此，您首先需要从集群中删除部署：

```
kubectl delete deployment -n dev voting-application-frontend
```

1.  创建`StorageClass`清单`sc.yaml`，内容如下。我们将使用`kubernetes.io/azure-disk`提供程序来使用 azureDisk 卷插件：

```
kind: StorageClass
apiVersion: storage.k8s.io/v1beta1
metadata:
  name: azure-disk
provisioner: kubernetes.io/azure-disk
parameters:
  storageaccounttype: Standard_LRS
  kind: Managed
```

1.  使用`kubectl apply -f sc.yaml`命令应用清单文件。

1.  将部署转换为 StatefulSet，并使用 Docker 镜像的`1.4.0`版本。完整的清单文件可以在[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter11/13_persistentvolume/voting-application.yaml`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter11/13_persistentvolume/voting-application.yaml)找到。我们将需要的更改与之前的`voting-application.yaml`清单文件进行对比，如下所示：

```
apiVersion: apps/v1
kind: StatefulSet
...
spec:
  replicas: 5
  serviceName: voting-application-frontend  # (1)
  ...
  template:
    ...
    spec:
      ...
      initContainers:  # (2)
      - name: volume-mount-permissions-fix
        image: packtpubkubernetesonwindows/voting-application:1.4.0
        command: ["powershell.exe", "-Command", "iisreset.exe /START; icacls.exe c:\\data /grant '\"IIS AppPool\\DefaultAppPool\":RW'"]
        volumeMounts:
        - mountPath: C:/data
          name: voting-log-volume
      containers:
      - name: frontend
        image: packtpubkubernetesonwindows/voting-application:1.4.0
        ...
        volumeMounts:  # (3)
        - mountPath: C:/data
          name: voting-log-volume
  volumeClaimTemplates:  # (4)
  - metadata:
      name: voting-log-volume
      labels:
        app: voting-application
    spec:
      accessModes:
        - ReadWriteOnce
      resources:
        requests:
          storage: 100Mi
      storageClassName: azure-disk
```

StatefulSet 需要提供负责此 StatefulSet 的服务名称（`1`）。除此之外，我们还定义了`volumeClaimTemplates`（`4`），用于为此 StatefulSet 中的每个 Pod 副本创建专用的 PersistentVolumeClaim。我们引用此 PVC 来将卷挂载为容器中的`C:/data`目录（`3`），其中`voting.log`将被持久化。此外，我们还需要为 IIS App Pool 用户提供适当的读/写权限以访问`C:/data`目录，否则 Web 应用程序将无法访问我们的 PersistentVolume。这是通过在`init`容器（`2`）中执行`icasls.exe`来实现的。请注意，您需要首先启动 IIS（`iisreset.exe /START`）以便在分配权限之前正确创建 IIS App Pool 用户！

1.  使用`kubectl apply -f .\voting-application.yaml`命令应用清单文件。

1.  当 StatefulSet 准备就绪时，打开网页浏览器并投几次票。

1.  在网页浏览器中打开`http://<serviceExternalIp>/Home/VotingLog`，根据您到达的 Pod 副本不同，您将看到不同的结果：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/a40d5661-8380-427f-88ca-7e156f2419d7.png)

好的，现在我们知道在容器中写入目录的操作正常工作。但让我们证明这个目录确实由 PersistentVolume 挂载支持。为此，请执行以下步骤：

1.  将`statefulset`缩减到`0`个副本。这将删除 StatefulSet 的所有 Pod：

```
kubectl scale statefulset/voting-application-frontend -n dev --replicas=0
```

1.  等待所有 Pod 终止，并使用`kubectl get pods -n dev`命令观察。

1.  扩展`statefulset`，例如，到`5`个副本：

```
kubectl scale statefulset/voting-application-frontend -n dev --replicas=5
```

1.  等待 Pod 创建并变为就绪。由于我们的就绪探针，这可能需要几分钟。

1.  在网页浏览器中导航至`http://<serviceExternalIp>/Home/VotingLog`。您应该看到每个 Pod 副本的投票日志完全相同。这表明所有 Pod 都像以前一样挂载了相同的 PersistentVolumes。

恭喜！您已成功在 Windows Pod 中为投票应用程序挂载了 azureDisk 持久卷。接下来，我们将看看如何为您的应用程序配置滚动更新。

# 为`Deployments`配置滚动更新

在生产场景中，您肯定需要一种部署策略，为您的应用程序提供零停机更新。作为容器编排器，Kubernetes 提供了不同的构建模块，可用于实现蓝绿部署、金丝雀部署或滚动部署。Kubernetes 部署对象完全支持执行滚动更新部署——在这种部署类型中，应用程序的新版本通过逐渐交换旧副本与新副本来推出，所有这些副本都在同一个服务后面。这意味着，在推出过程中，最终用户将访问应用程序的旧版本或新版本之一。

为了确保在 Kubernetes 中对部署进行真正的零停机更新，您需要配置适当的探测器，特别是就绪性。通过这种方式，只有当副本能够正确响应请求时，用户才会被重定向到一个副本。

让我们看看如何为投票应用程序实现滚动部署。实际上，在先前的示例中，我们已经在使用这种方法，现在我们将更详细地解释配置。按照以下步骤：

1.  使用 `kubectl delete statefulset -n dev voting-application-frontend` 命令删除我们在上一节中创建的 StatefulSet。

1.  让我们回到我们用于 HPA 演示的 `voting-application.yaml` 部署清单文件。您可以在 GitHub 仓库中找到该文件，网址为 [`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter11/14_rollingupdate/voting-application.yaml`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter11/14_rollingupdate/voting-application.yaml)。

1.  滚动更新部署的配置如下：

```
apiVersion: apps/v1
kind: Deployment
metadata:
  namespace: dev
  name: voting-application-frontend
  ...
spec:
  replicas: 5
  minReadySeconds: 5
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxUnavailable: 1
      maxSurge: 1
  ...
    spec:
      ...
      containers:
      - name: frontend
        image: packtpubkubernetesonwindows/voting-application:1.2.0
        ...
```

为了为 Deployment 对象定义滚动更新部署的关键部分是`strategy`。要配置滚动更新，您需要使用`type`和`RollingUpdate`值（这也是默认值）。另一种方法是使用 recreate，它将简单地杀死所有 Pod，然后创建新的 Pod——通常情况下，除非与更复杂的模式（如蓝绿部署）结合使用，您不希望在生产中使用这种策略类型。对于`RollingUpdate`类型，您可以定义`maxUnavailable`，它表示在更新期间有多少个 Pod 可以处于非就绪状态。同样，`maxSurge`定义了在部署期间可以创建的 Pod 的最大数量，超过所需 Pod 数量。您可以将这些值指定为数字或百分比——默认情况下，它们都设置为 25%。为了更好地理解这些数字在实践中的含义，让我们分析一下我们的例子。当您触发 Deployment 的部署时，希望的副本数量为`5`，可能会发生以下事件序列：

+   +   创建了一个新的 Pod。现在，我们总共有六个 Pod，所以我们已经达到了`maxSurge`设置的限制。

+   `maxUnavailable`设置为`1`，我们有五个就绪的 Pod，所以可以终止一个旧的 Pod。我们总共有五个 Pod，其中四个是就绪的。

+   创建了一个新的 Pod。现在我们总共有六个 Pod，但只有四个是就绪的。部署必须等待更多的 Pod 就绪才能继续。

+   其中一个新的 Pod 就绪了。我们总共有六个 Pod，其中五个是就绪的，这意味着一个旧的 Pod 可以被终止，然后创建一个新的 Pod。

+   这个过程逐渐持续，直到所有五个新的 Pod 都就绪为止。

1.  让我们看看它在实践中是如何工作的。首先，使用`kubectl apply -f .\voting-application.yaml`命令应用清单文件——这将创建应用的初始版本。

1.  对现有部署的滚动更新可以通过实时编辑对象或使用`kubectl rollout`命令来进行。一般来说，最好使用声明性方法：更改清单文件，然后再次应用。在清单文件中将容器镜像标签更改为`packtpubkubernetesonwindows/voting-application:1.4.0`，然后使用`kubectl apply -f .\voting-application.yaml`命令进行应用。

1.  在那之后，立即开始使用以下命令观察`rollout status`：

```
PS C:\src> kubectl rollout status -n dev deployment/voting-application-frontend
Waiting for deployment "voting-application-frontend" rollout to finish: 2 out of 5 new replicas have been updated...
Waiting for deployment "voting-application-frontend" rollout to finish: 3 out of 5 new replicas have been updated...
Waiting for deployment "voting-application-frontend" rollout to finish: 4 out of 5 new replicas have been updated...
Waiting for deployment "voting-application-frontend" rollout to finish: 1 old replicas are pending termination...
Waiting for deployment "voting-application-frontend" rollout to finish: 4 of 5 updated replicas are available...
deployment "voting-application-frontend" successfully rolled out
```

1.  在部署过程中，您可以使用诸如`kubectl rollout undo -n dev deployment/voting-application-frontend`或`kubectl rollout pause -n dev deployment/voting-application-frontend`之类的命令来控制部署的滚动。但是，您也可以通过修改清单文件并再次应用来实现相同的效果，甚至包括暂停。

1.  您可以在部署过程中尝试访问应用程序。我们已经正确配置了就绪探针，因此您不会遇到应用程序的意外响应！

StatefulSets 也具有可定制的部署策略。由于状态持久性，该策略与部署的策略有些不同。您可以在官方文档中阅读更多内容，网址为[`kubernetes.io/docs/concepts/workloads/controllers/statefulset/#update-strategies`](https://kubernetes.io/docs/concepts/workloads/controllers/statefulset/#update-strategies)。

现在，让我们专注于 Kubernetes 中的另一个重要主题：基于角色的访问控制（RBAC）。

# 基于角色的访问控制

Kubernetes 带有内置的 RBAC 机制，允许您配置细粒度的权限集并将其分配给用户、组和服务账户（主体）。通过这种方式，作为集群管理员，您可以控制集群用户（内部和外部）与 API 服务器的交互方式，他们可以访问哪些 API 资源以及可以执行哪些操作（动词）。

Kubernetes 中的身份验证是高度可配置和可扩展的；您可以在官方文档中阅读更多内容，网址为[`kubernetes.io/docs/reference/access-authn-authz/authentication/`](https://kubernetes.io/docs/reference/access-authn-authz/authentication/)。在 AKS Engine 集群中，可以轻松集成 Azure Active Directory（AAD）；您可以在[`github.com/Azure/aks-engine/blob/master/docs/topics/aad.md`](https://github.com/Azure/aks-engine/blob/master/docs/topics/aad.md)找到更多详细信息。

使用 RBAC 涉及两组 API 资源：

+   `Role`和`ClusterRole`：它们定义了一组权限。`Role`中的每个规则都说明了允许对哪些 API 资源使用哪些动词。`Role`和`ClusterRole`之间唯一的区别是`Role`是命名空间范围的，而`ClusterRole`不是。

+   `RoleBinding`和`ClusterRoleBinding`：它们将用户或一组用户与给定角色关联起来。类似地，`RoleBinding`是命名空间范围的，`ClusterRoleBinding`是集群范围的。`ClusterRoleBinding`与`ClusterRole`配合使用，`RoleBinding`与`ClusterRole`或`Role`配合使用。

Kubernetes 使用宽松的 RBAC 模型 - 没有拒绝规则；默认情况下拒绝一切，并且您必须定义允许规则。RBAC 的使用有详细的文档，并且所有功能都在官方文档中介绍，可在[`kubernetes.io/docs/reference/access-authn-authz/rbac/`](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)上找到。您应该考虑 RBAC 策略的两个关键点：

+   使用最小权限原则。您的应用程序应仅访问其自己的资源（建议您使用具有对该应用程序的 Secrets 或 ConfigMaps 访问权限的专用服务帐户来运行每个应用程序）。用户应根据其在项目中的角色拥有受限制的访问权限（例如，QA 工程师可能只需要对集群具有只读访问权限）。

+   将`RoleBinding`分配给组而不是单个用户。这将使您的权限管理更加容易。请注意，这需要与外部身份验证提供程序集成才能发挥最佳作用。

让我们演示如何使用`Role`和`RoleBinding`来限制对部署的访问权限，使其仅能访问最少的所需 ConfigMaps 和 Secrets。我们将为 ASP.NET MVC 应用程序执行此操作，并且使用类似的方法可以作为额外的练习用于 SQL Server。为此，我们将使用用于演示 ConfigMaps 的投票应用程序 Docker 镜像`packtpubkubernetesonwindows/voting-application:1.3.0`。此部署在运行时需要 ConfigMaps 和 Secrets。请按照以下步骤配置 RBAC：

1.  创建`serviceaccount.yaml`清单文件，用于专用 ServiceAccount，命名为`voting-application`：

```
apiVersion: v1
kind: ServiceAccount
metadata:
  name: voting-application
  namespace: dev
```

1.  使用`kubectl apply -f .\serviceaccount.yaml`命令应用清单文件。

1.  为`Role`创建`role.yaml`清单文件，用于读取应用程序的 Secrets 和 ConfigMaps：

```
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: dev
  name: voting-application-data-reader
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  resourceNames: ["voting-application-customerrors-config"]
  verbs: ["get"]
- apiGroups: [""]
  resources: ["secret"]
  resourceNames: ["mssql"]
  verbs: ["get"]
```

1.  使用`kubectl auth reconcile -f .\role.yaml`命令来应用`Role`。建议使用`kubectl auth reconcile`而不是`kubectl apply`。

1.  为`RoleBinding`创建`rolebinding.yaml`清单文件，将我们的 ServiceAccount 与前面的角色关联起来：

```
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  namespace: dev
  name: voting-application-data-reader
subjects:
- kind: ServiceAccount
  name: voting-application
roleRef:
  kind: Role
  name: voting-application-data-reader
  apiGroup: rbac.authorization.k8s.io
```

1.  使用`kubectl auth reconcile -f .\rolebinding.yaml`命令应用`RoleBinding`。

1.  检查 RBAC 是否允许 ServiceAccount 访问 ConfigMap。您可以使用`kubectl auth can-i get configmap/voting-application-customerrors-config -n dev --as system:serviceaccount:dev:voting-application`命令，或者使用`kubectl auth can-i --list -n dev --as system:serviceaccount:dev:voting-application`命令可视化所有可访问的 API 资源。

1.  修改`voting-application.yaml`清单文件，使部署使用`voting-application` ServiceAccount：

```
apiVersion: apps/v1
kind: Deployment
metadata:
  namespace: dev
  name: voting-application-frontend
  ...
spec:
  ...
  template:
    ...
    spec:
      serviceAccountName: voting-application
      ...
```

1.  使用`kubectl apply -f .\voting-application.yaml`命令应用部署清单文件。

您可以执行类似的操作，例如通过定义允许对所有 API 资源进行只读访问的角色来为集群中的用户进行操作。

恭喜！您已成功为投票应用程序设置了 RBAC。

# 摘要

在本章中，我们演示了 Kubernetes 的几个常用高级功能。首先，您了解了 Kubernetes 中命名空间的目的以及如何管理它们。然后，我们介绍了就绪、存活和启动探针，这些用于监视 Pod 容器的生命周期，并为您提供了一组在处理探针时的推荐实践以及如何避免常见陷阱。接下来是学习如何指定 Pod 资源请求和限制，以及如何结合 HPA 进行自动缩放。为了将配置数据（包括敏感密码）注入到我们的应用程序中，我们使用了 ConfigMaps 和 Secrets。除此之外，我们还演示了如何在运行在 Windows 节点上的 StatefulSets 中使用 PersistentVolumes（由 azureDisk Volume 插件支持）。最后，您了解了如何处理部署对象的滚动更新，以及 Kubernetes 中 RBAC 的目的。

下一章将重点介绍使用 Kubernetes 的开发工作流程，以及在创建 Kubernetes 应用程序时如何与其他开发人员合作。

# 问题

1.  何时应考虑使用 Kubernetes 命名空间？

1.  就绪和存活探针之间有什么区别？

1.  使用不当配置的存活探针有哪些风险？

1.  Pod 容器的资源`requests`和`limits`值有什么区别？

1.  HPA 中冷却延迟的目的是什么？

1.  ConfigMaps 和 Secrets 之间有什么区别？

1.  StatefulSet 规范中的`volumeClaimTemplates`是什么？

1.  在使用滚动更新部署时，为什么要确保就绪探针的正确配置？

1.  在 Kubernetes 中使用 RBAC 时，最重要的经验法则是什么？

您可以在本书的*评估*部分找到这些问题的答案。

# 进一步阅读

+   有关 Kubernetes 功能和应用程序管理的更多信息，请参考以下 Packt 图书：

+   *The Complete Kubernetes Guide* by Jonathan Baier, Gigi Sayfan, Et al ([`www.packtpub.com/virtualization-and-cloud/complete-kubernetes-guide`](https://www.packtpub.com/virtualization-and-cloud/complete-kubernetes-guide)).

+   *Getting Started with Kubernetes - Third Edition* by Jonathan Baier, Jesse White ([`www.packtpub.com/virtualization-and-cloud/getting-started-kubernetes-third-edition`](https://www.packtpub.com/virtualization-and-cloud/getting-started-kubernetes-third-edition)).

+   *Kubernetes for Developers* by Joseph Heck ([`www.packtpub.com/virtualization-and-cloud/kubernetes-developers`](https://www.packtpub.com/virtualization-and-cloud/kubernetes-developers)).
