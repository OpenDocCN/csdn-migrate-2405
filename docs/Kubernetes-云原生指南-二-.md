# Kubernetes 云原生指南（二）

> 原文：[`zh.annas-archive.org/md5/58DD843CC49B42503E619A37722EEB6C`](https://zh.annas-archive.org/md5/58DD843CC49B42503E619A37722EEB6C)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：服务和 Ingress-与外部世界通信

本章包含了 Kubernetes 提供的方法的全面讨论，允许应用程序相互通信，以及与集群外部的资源通信。您将了解 Kubernetes 服务资源及其所有可能的类型-ClusterIP、NodePort、LoadBalancer 和 ExternalName-以及如何实现它们。最后，您将学习如何使用 Kubernetes Ingress。

在本章中，我们将涵盖以下主题：

+   理解服务和集群 DNS

+   实现 ClusterIP

+   使用 NodePort

+   设置 LoadBalancer 服务

+   创建 ExternalName 服务

+   配置 Ingress

# 技术要求

为了运行本章中详细介绍的命令，您需要一台支持`kubectl`命令行工具的计算机，以及一个可用的 Kubernetes 集群。请查看*第一章*，*与 Kubernetes 通信*，了解快速启动和运行 Kubernetes 的几种方法，以及如何安装`kubectl`工具的说明。

本章中使用的代码可以在书籍的 GitHub 存储库中找到，网址为[`github.com/PacktPublishing/Cloud-Native-with-Kubernetes/tree/master/Chapter5`](https://github.com/PacktPublishing/Cloud-Native-with-Kubernetes/tree/master/Chapter5)。

# 理解服务和集群 DNS

在过去的几章中，我们已经讨论了如何有效地在 Kubernetes 上运行应用程序，使用包括 Pods、Deployments 和 StatefulSets 在内的资源。然而，许多应用程序，如 Web 服务器，需要能够接受来自其容器外部的网络请求。这些请求可能来自其他应用程序，也可能来自访问公共互联网的设备。

Kubernetes 提供了几种资源类型，用于处理允许集群外部和内部资源访问运行在 Pods、Deployments 等应用程序的各种情况。

这些属于两种主要资源类型，服务和 Ingress：

+   **服务**有几种子类型-ClusterIP、NodePort 和 LoadBalancer-通常用于提供从集群内部或外部简单访问单个应用程序。

+   Ingress 是一个更高级的资源，它创建一个控制器，负责基于路径名和主机名的路由到集群内运行的各种资源。Ingress 通过使用规则将流量转发到服务来工作。您需要使用服务来使用 Ingress。

在我们开始第一种类型的服务资源之前，让我们回顾一下 Kubernetes 如何处理集群内部的 DNS。

## 集群 DNS

让我们首先讨论在 Kubernetes 中哪些资源默认拥有自己的 DNS 名称。Kubernetes 中的 DNS 名称仅限于 Pod 和服务。Pod DNS 名称包含几个部分，结构化为子域。

在 Kubernetes 中运行的 Pod 的典型完全限定域名（FQDN）如下所示：

```
my-hostname.my-subdomain.my-namespace.svc.my-cluster-domain.example
```

让我们从最右边开始分解：

+   `my-cluster-domain.example`对应于 Cluster API 本身的配置 DNS 名称。根据用于设置集群的工具以及其运行的环境，这可以是外部域名或内部 DNS 名称。

+   `svc`是一个部分，即使在 Pod DNS 名称中也会出现 - 因此我们可以假设它会在那里。但是，正如您很快会看到的，您通常不会通过它们的 FQDN 访问 Pod 或服务。

+   `my-namespace`相当容易理解。DNS 名称的这一部分将是您的 Pod 所在的命名空间。

+   `my-subdomain`对应于 Pod 规范中的`subdomain`字段。这个字段是完全可选的。

+   最后，`my-hostname`将设置为 Pod 在 Pod 元数据中的名称。

总的来说，这个 DNS 名称允许集群中的其他资源访问特定的 Pod。这通常本身并不是很有用，特别是如果您正在使用通常有多个 Pod 的部署和有状态集。这就是服务的用武之地。

让我们来看看服务的 A 记录 DNS 名称：

```
my-svc.my-namespace.svc.cluster-domain.example
```

正如您所看到的，这与 Pod DNS 名称非常相似，不同之处在于我们在命名空间左侧只有一个值 - 就是服务名称（与 Pod 一样，这是基于元数据名称生成的）。

这些 DNS 名称的处理方式的一个结果是，在命名空间内，您可以仅通过其服务（或 Pod）名称和子域访问服务或 Pod。

例如，以前的服务 DNS 名称。在`my-namespace`命名空间内，可以通过 DNS 名称`my-svc`简单地访问服务。在`my-namespace`之外，可以通过`my-svc.my-namespace`访问服务。

现在我们已经了解了集群内 DNS 的工作原理，我们可以讨论这如何转化为服务代理。

## 服务代理类型

服务，尽可能简单地解释，提供了一个将请求转发到一个或多个运行应用程序的 Pod 的抽象。

创建服务时，我们定义了一个选择器，告诉服务将请求转发到哪些 Pod。通过`kube-proxy`组件的功能，当请求到达服务时，它们将被转发到与服务选择器匹配的各个 Pod。

在 Kubernetes 中，有三种可能的代理模式：

+   **用户空间代理模式**：最古老的代理模式，自 Kubernetes 版本 1.0 以来可用。这种代理模式将以轮询方式将请求转发到匹配的 Pod。

+   **Iptables 代理模式**：自 1.1 版本以来可用，并且自 1.2 版本以来是默认选项。这比用户空间模式的开销要低，并且可以使用轮询或随机选择。

+   **IPVS 代理模式**：自 1.8 版本以来提供的最新选项。此代理模式允许其他负载平衡选项（不仅仅是轮询）：

a. 轮询

b. 最少连接（最少数量的打开连接）

c. 源哈希

d. 目标哈希

e. 最短预期延迟

f. 从不排队

与此列表相关的是对轮询负载均衡的讨论，对于那些不熟悉的人。

轮询负载均衡涉及循环遍历潜在的服务端点列表，每个网络请求一次。以下图表显示了这个过程的简化视图，它与 Kubernetes 服务后面的 Pod 相关：

![图 5.1 - 服务负载均衡到 Pods](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cld-ntv-k8s/img/B14790_05_001.jpg)

图 5.1 - 服务负载均衡到 Pods

正如您所看到的，服务会交替将请求发送到不同的 Pod。第一个请求发送到 Pod A，第二个发送到 Pod B，第三个发送到 Pod C，然后循环。现在我们知道服务实际上如何处理请求了，让我们来回顾一下主要类型的服务，从 ClusterIP 开始。

# 实现 ClusterIP

ClusterIP 是在集群内部公开的一种简单类型的服务。这种类型的服务无法从集群外部访问。让我们来看看我们服务的 YAML 文件：

clusterip-service.yaml

```
apiVersion: v1
kind: Service
metadata:
  name: my-svc
Spec:
  type: ClusterIP
  selector:
    app: web-application
    environment: staging
  ports:
    - name: http
      protocol: TCP
      port: 80
      targetPort: 8080
```

与其他 Kubernetes 资源一样，我们有我们的元数据块和我们的`name`值。正如您可以从我们关于 DNS 的讨论中回忆起来，这个`name`值是您如何可以从集群中的其他地方访问您的服务的。因此，ClusterIP 是一个很好的选择，适用于只需要被集群内其他 Pod 访问的服务。

接下来，我们有我们的`Spec`，它由三个主要部分组成：

+   首先，我们有我们的`type`，它对应于我们服务的类型。由于默认类型是`ClusterIP`，如果您想要一个 ClusterIP 服务，实际上不需要指定类型。

+   接下来，我们有我们的`selector`。我们的`selector`由键值对组成，必须与相关 Pod 的元数据中的标签匹配。在这种情况下，我们的服务将寻找具有`app=web-application`和`environment=staging`标签的 Pod 来转发流量。

+   最后，我们有我们的`ports`块，我们可以将服务上的端口映射到我们 Pod 上的`targetPort`号码。在这种情况下，我们服务上的端口`80`（HTTP 端口）将映射到我们应用程序 Pod 上的端口`8080`。我们的服务可以打开多个端口，但在打开多个端口时，`name`字段是必需的。

接下来，让我们深入审查`protocol`选项，因为这些对我们讨论服务端口很重要。

## 协议

在我们之前的 ClusterIP 服务的情况下，我们选择了`TCP`作为我们的协议。截至目前（截至版本 1.19），Kubernetes 支持多种协议：

+   **TCP**

+   **UDP**

+   **HTTP**

+   **PROXY**

+   **SCTP**

这是一个新功能可能会出现的领域，特别是涉及 HTTP（L7）服务的地方。目前，在不同环境或云提供商中，并不完全支持所有这些协议。

重要提示

有关更多信息，您可以查看主要的 Kubernetes 文档（[`kubernetes.io/docs/concepts/services-networking/service/`](https://kubernetes.io/docs/concepts/services-networking/service/)）了解当前服务协议的状态。

现在我们已经讨论了 Cluster IP 的服务 YAML 的具体内容，我们可以继续下一个类型的服务 - NodePort。

# 使用 NodePort

NodePort 是一种面向外部的服务类型，这意味着它实际上可以从集群外部访问。创建 NodePort 服务时，将自动创建同名的 ClusterIP 服务，并由 NodePort 路由到，因此您仍然可以从集群内部访问服务。这使 NodePort 成为在无法或不可能使用 LoadBalancer 服务时外部访问应用程序的良好选择。

NodePort 听起来像它的名字 - 这种类型的服务在集群中的每个节点上打开一个可以访问服务的端口。这个端口默认在`30000`-`32767`之间，并且在服务创建时会自动链接。

以下是我们的 NodePort 服务 YAML 的样子：

NodePort 服务.yaml

```
apiVersion: v1
kind: Service
metadata:
  name: my-svc
Spec:
  type: NodePort
  selector:
    app: web-application
  ports:
    - name: http
      protocol: TCP
      port: 80
      targetPort: 8080
```

正如您所看到的，与 ClusterIP 服务唯一的区别是服务类型 - 然而，重要的是要注意，我们在“端口”部分中的预期端口`80`只有在访问自动创建的 ClusterIP 版本的服务时才会被使用。从集群外部，我们需要查看生成的端口链接以访问我们的节点 IP 上的服务。

为了做到这一点，我们可以使用以下命令创建我们的服务：

```
kubectl apply -f svc.yaml 
```

然后运行这个命令：

```
kubectl describe service my-svc
```

上述命令的结果将是以下输出：

```
Name:                   my-svc
Namespace:              default
Labels:                 app=web-application
Annotations:            <none>
Selector:               app=web-application
Type:                   NodePort
IP:                     10.32.0.8
Port:                   <unset> 8080/TCP
TargetPort:             8080/TCP
NodePort:               <unset> 31598/TCP
Endpoints:              10.200.1.3:8080,10.200.1.5:8080
Session Affinity:       None
Events:                 <none>
```

从这个输出中，我们看`NodePort`行，看到我们为这个服务分配的端口是`31598`。因此，这个服务可以在任何节点上通过`[NODE_IP]:[ASSIGNED_PORT]`访问。

或者，我们可以手动为服务分配一个 NodePort IP。手动分配 NodePort 的 YAML 如下：

手动 NodePort 服务.yaml

```
apiVersion: v1
kind: Service
metadata:
  name: my-svc
Spec:
  type: NodePort
  selector:
    app: web-application
  ports:
    - name: http
      protocol: TCP
      port: 80
      targetPort: 8080
      nodePort: 31233
```

正如您所看到的，我们选择了一个在`30000`-`32767`范围内的`nodePort`，在这种情况下是`31233`。要确切地了解这个 NodePort 服务在节点之间是如何工作的，请看下面的图表：

![图 5.2 - NodePort 服务](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cld-ntv-k8s/img/B14790_05_002.jpg)

图 5.2 - NodePort 服务

正如您所看到的，虽然服务可以在集群中的每个节点（节点 A、节点 B 和节点 C）访问，但网络请求仍然在所有节点的 Pod（Pod A、Pod B 和 Pod C）之间进行负载均衡，而不仅仅是访问的节点。这是确保应用程序可以从任何节点访问的有效方式。然而，在使用云服务时，您已经有了一系列工具来在服务器之间分发请求。下一个类型的服务，LoadBalancer，让我们在 Kubernetes 的上下文中使用这些工具。

# 设置 LoadBalancer 服务

LoadBalancer 是 Kubernetes 中的特殊服务类型，根据集群运行的位置提供负载均衡器。例如，在 AWS 中，Kubernetes 将提供弹性负载均衡器。

重要提示

有关 LoadBalancer 服务和配置的完整列表，请查阅 Kubernetes 服务文档，网址为[`kubernetes.io/docs/concepts/services-networking/service/#loadbalancer`](https://kubernetes.io/docs/concepts/services-networking/service/#loadbalancer)。

与`ClusterIP`或 NodePort 不同，我们可以以特定于云的方式修改 LoadBalancer 服务的功能。通常，这是通过服务 YAML 文件中的注释块完成的-正如我们之前讨论的那样，它只是一组键和值。要了解如何在 AWS 中完成此操作，让我们回顾一下 LoadBalancer 服务的规范：

loadbalancer-service.yaml

```
apiVersion: v1
kind: Service
metadata:
  name: my-svc
  annotations:
    service.beta.kubernetes.io/aws-load-balancer-ssl-cert: arn:aws.. 
spec:
  type: LoadBalancer
  selector:
    app: web-application
  ports:
    - name: http
      protocol: TCP
      port: 80
      targetPort: 8080
```

虽然我们可以创建没有任何注释的 LoadBalancer，但是支持的 AWS 特定注释使我们能够（如前面的 YAML 代码所示）指定要附加到我们的负载均衡器的 TLS 证书（通过其在 Amazon 证书管理器中的 ARN）。AWS 注释还允许配置负载均衡器的日志等。

以下是 AWS 云提供商支持的一些关键注释，截至本书编写时：

+   `service.beta.kubernetes.io/aws-load-balancer-ssl-cert`

+   `service.beta.kubernetes.io/aws-load-balancer-proxy-protocol`

+   `service.beta.kubernetes.io/aws-load-balancer-ssl-ports`

重要提示

有关所有提供商的注释和解释的完整列表可以在官方 Kubernetes 文档的**云提供商**页面上找到，网址为[`kubernetes.io/docs/tasks/administer-cluster/running-cloud-controller/`](https://kubernetes.io/docs/tasks/administer-cluster/running-cloud-controller/)。

最后，通过 LoadBalancer 服务，我们已经涵盖了您可能最常使用的服务类型。但是，对于服务本身在 Kubernetes 之外运行的特殊情况，我们可以使用另一种服务类型：ExternalName。

# 创建 ExternalName 服务

类型为 ExternalName 的服务可用于代理实际未在集群上运行的应用程序，同时仍保持服务作为可以随时更新的抽象层。

让我们来设定场景：你有一个在 Azure 上运行的传统生产应用程序，你希望从集群内部访问它。你可以在`myoldapp.mydomain.com`上访问这个传统应用程序。然而，你的团队目前正在将这个应用程序容器化，并在 Kubernetes 上运行它，而这个新版本目前正在你的`dev`命名空间环境中在你的集群上运行。

与其要求你的其他应用程序根据环境对不同的地方进行通信，你可以始终在你的生产（`prod`）和开发（`dev`）命名空间中都指向一个名为`my-svc`的 Service。

在`dev`中，这个 Service 可以是一个指向你的新容器化应用程序的 Pods 的`ClusterIP` Service。以下 YAML 显示了开发中的容器化 Service 应该如何工作：

clusterip-for-external-service.yaml

```
apiVersion: v1
kind: Service
metadata:
  name: my-svc
  namespace: dev
Spec:
  type: ClusterIP
  selector:
    app: newly-containerized-app
  ports:
    - name: http
      protocol: TCP
      port: 80
      targetPort: 8080
```

在`prod`命名空间中，这个 Service 将会是一个`ExternalName` Service：

externalname-service.yaml

```
apiVersion: v1
kind: Service
metadata:
  name: my-svc
  namespace: prod
spec:
  type: ExternalName
  externalName: myoldapp.mydomain.com
```

由于我们的`ExternalName` Service 实际上并不转发请求到 Pods，所以我们不需要一个选择器。相反，我们指定一个`ExternalName`，这是我们希望 Service 指向的 DNS 名称。

以下图表显示了如何在这种模式中使用`ExternalName` Service：

![图 5.3 - ExternalName Service 配置](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cld-ntv-k8s/img/B14790_05_003.jpg)

图 5.3 - ExternalName Service 配置

在上图中，我们的**EC2 Running Legacy Application**是一个 AWS VM，不属于集群。我们的类型为**ExternalName**的**Service B**将请求路由到 VM。这样，我们的**Pod C**（或集群中的任何其他 Pod）可以通过 ExternalName 服务的 Kubernetes DNS 名称简单地访问我们的外部传统应用程序。

通过`ExternalName`，我们已经完成了对所有 Kubernetes Service 类型的审查。让我们继续讨论一种更复杂的暴露应用程序的方法 - Kubernetes Ingress 资源。

# 配置 Ingress

正如本章开头提到的，Ingress 提供了一个将请求路由到集群中的细粒度机制。Ingress 并不取代 Services，而是通过诸如基于路径的路由等功能来增强它们。为什么这是必要的？有很多原因，包括成本。一个具有 10 个路径到`ClusterIP` Services 的 Ingress 比为每个路径创建一个新的 LoadBalancer Service 要便宜得多 - 而且它保持了事情简单和易于理解。

Ingress 与 Kubernetes 中的其他服务不同。仅仅创建 Ingress 本身是不会有任何作用的。您需要两个额外的组件：

+   Ingress 控制器：您可以选择许多实现，构建在诸如 Nginx 或 HAProxy 等工具上。

+   用于预期路由的 ClusterIP 或 NodePort 服务。

首先，让我们讨论如何配置 Ingress 控制器。

## Ingress 控制器

一般来说，集群不会预先配置任何现有的 Ingress 控制器。您需要选择并部署一个到您的集群中。`ingress-nginx` 可能是最受欢迎的选择，但还有其他几种选择 - 请参阅[`kubernetes.io/docs/concepts/services-networking/ingress-controllers/`](https://kubernetes.io/docs/concepts/services-networking/ingress-controllers/)获取完整列表。

让我们学习如何部署 Ingress 控制器 - 为了本书的目的，我们将坚持使用由 Kubernetes 社区创建的 Nginx Ingress 控制器 `ingress-nginx`。

安装可能因控制器而异，但对于 `ingress-nginx`，有两个主要部分。首先，要部署主控制器本身，请运行以下命令，具体取决于目标环境和最新的 Nginx Ingress 版本：

```
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v0.41.2/deploy/static/provider/cloud/deploy.yaml
```

其次，我们可能需要根据我们运行的环境来配置我们的 Ingress。对于在 AWS 上运行的集群，我们可以配置 Ingress 入口点以使用我们在 AWS 中创建的弹性负载均衡器。

重要提示

要查看所有特定于环境的设置说明，请参阅 `ingress-nginx` 文档[`kubernetes.github.io/ingress-nginx/deploy/`](https://kubernetes.github.io/ingress-nginx/deploy/)。

Nginx Ingress 控制器是一组 Pod，它将在创建新的 Ingress 资源（自定义的 Kubernetes 资源）时自动更新 Nginx 配置。除了 Ingress 控制器，我们还需要一种方式将请求路由到 Ingress 控制器 - 称为入口点。

### Ingress 入口点

默认的 `nginx-ingress` 安装还将创建一个服务，用于为 Nginx 层提供请求，此时 Ingress 规则接管。根据您配置 Ingress 的方式，这可以是一个负载均衡器或节点端口服务。在云环境中，您可能会使用云负载均衡器服务作为集群 Ingress 的入口点。

### Ingress 规则和 YAML

既然我们的 Ingress 控制器已经启动并运行，我们可以开始配置我们的 Ingress 规则了。

让我们从一个简单的例子开始。我们有两个服务，`service-a`和`service-b`，我们希望通过我们的 Ingress 在不同的路径上公开它们。一旦您的 Ingress 控制器和任何相关的弹性负载均衡器被创建（假设我们在 AWS 上运行），让我们首先通过以下步骤来创建我们的服务：

1.  首先，让我们看看如何在 YAML 中创建服务 A。让我们将文件命名为`service-a.yaml`：

service-a.yaml

```
apiVersion: v1
kind: Service
metadata:
  name: service-a
Spec:
  type: ClusterIP
  selector:
    app: application-a
  ports:
    - name: http
      protocol: TCP
      port: 80
      targetPort: 8080
```

1.  您可以通过运行以下命令来创建我们的服务 A：

```
kubectl apply -f service-a.yaml
```

1.  接下来，让我们创建我们的服务 B，其 YAML 代码看起来非常相似：

```
apiVersion: v1
kind: Service
metadata:
  name: service-b
Spec:
  type: ClusterIP
  selector:
    app: application-b
  ports:
    - name: http
      protocol: TCP
      port: 80
      targetPort: 8000
```

1.  通过运行以下命令来创建我们的服务 B：

```
kubectl apply -f service-b.yaml
```

1.  最后，我们可以为每个路径创建 Ingress 规则。以下是我们的 Ingress 的 YAML 代码，根据基于路径的路由规则，将根据需要拆分请求：

ingress.yaml

```
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: my-first-ingress
  annotations:
    nginx.ingress.kubernetes.io/rewrite-target: /
spec:
  rules:
  - host: my.application.com
    http:
      paths:
      - path: /a
        backend:
          serviceName: service-a
          servicePort: 80
      - path: /b
        backend:
          serviceName: service-b
          servicePort: 80
```

在我们之前的 YAML 中，ingress 有一个单一的`host`值，这对应于通过 Ingress 传入的流量的主机请求头。然后，我们有两个路径，`/a`和`/b`，它们分别指向我们之前创建的两个`ClusterIP`服务。为了将这个配置以图形的形式呈现出来，让我们看一下下面的图表：

![图 5.4 - Kubernetes Ingress 示例](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cld-ntv-k8s/img/B14790_05_004.jpg)

图 5.4 - Kubernetes Ingress 示例

正如您所看到的，我们简单的基于路径的规则导致网络请求直接路由到正确的 Pod。这是因为`nginx-ingress`使用服务选择器来获取 Pod IP 列表，但不直接使用服务与 Pod 通信。相反，Nginx（在这种情况下）配置会在新的 Pod IP 上线时自动更新。

`host`值实际上并不是必需的。如果您将其省略，那么通过 Ingress 传入的任何流量，无论主机头如何（除非它匹配指定主机的不同规则），都将根据规则进行路由。以下的 YAML 显示了这一点：

ingress-no-host.yaml

```
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: my-first-ingress
  annotations:
    nginx.ingress.kubernetes.io/rewrite-target: /
spec:
  rules:
   - http:
      paths:
      - path: /a
        backend:
          serviceName: service-a
          servicePort: 80
      - path: /b
        backend:
          serviceName: service-b
          servicePort: 80
```

这个先前的 Ingress 定义将流量流向基于路径的路由规则，即使没有主机头值。

同样，也可以根据主机头将流量分成多个独立的分支路径，就像这样：

ingress-branching.yaml

```
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: multiple-branches-ingress
spec:
  rules:
  - host: my.application.com
    http:
      paths:
      - backend:
          serviceName: service-a
          servicePort: 80
  - host: my.otherapplication.com
    http:
      paths:
      - backend:
          serviceName: service-b
          servicePort: 80
```

最后，在许多情况下，您还可以使用 TLS 来保护您的 Ingress，尽管这个功能在每个 Ingress 控制器的基础上有所不同。对于 Nginx，可以使用 Kubernetes Secret 来实现这一点。我们将在下一章介绍这个功能，但现在，请查看 Ingress 端的配置：

ingress-secure.yaml

```
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: secured-ingress
spec:
  tls:
  - hosts:
    - my.application.com
    secretName: my-tls-secret
  rules:
    - host: my.application.com
      http:
        paths:
        - path: /
          backend:
            serviceName: service-a
            servicePort: 8080
```

此配置将查找名为`my-tls-secret`的 Kubernetes Secret，以附加到 Ingress 以进行 TLS。

这结束了我们对 Ingress 的讨论。Ingress 的许多功能可能取决于您决定使用的 Ingress 控制器，因此请查看您选择的实现的文档。

# 摘要

在本章中，我们回顾了 Kubernetes 提供的各种方法，以便将在集群上运行的应用程序暴露给外部世界。主要方法是服务和 Ingress。在服务中，您可以使用 ClusterIP 服务进行集群内路由，使用 NodePort 直接通过节点上的端口访问服务。LoadBalancer 服务允许您使用现有的云负载均衡系统，而 ExternalName 服务允许您将请求路由到集群外部的资源。

最后，Ingress 提供了一个强大的工具，可以通过路径在集群中路由请求。要实现 Ingress，您需要在集群上安装第三方或开源 Ingress 控制器。

在下一章中，我们将讨论如何使用 ConfigMap 和 Secret 两种资源类型将配置信息注入到在 Kubernetes 上运行的应用程序中。

# 问题

1.  对于仅在集群内部访问的应用程序，您会使用哪种类型的服务？

1.  您如何确定 NodePort 服务正在使用哪个端口？

1.  为什么 Ingress 比纯粹的服务更具成本效益？

1.  除了支持传统应用程序外，在云平台上 ExternalName 服务可能有什么用处？

# 进一步阅读

+   有关云提供商的信息，请参阅 Kubernetes 文档：[`kubernetes.io/docs/tasks/administer-cluster/running-cloud-controller/`](https://kubernetes.io/docs/tasks/administer-cluster/running-cloud-controller/)


# 第六章：Kubernetes 应用程序配置

本章描述了 Kubernetes 提供的主要配置工具。我们将首先讨论一些将配置注入到容器化应用程序中的最佳实践。接下来，我们将讨论 ConfigMaps，这是 Kubernetes 旨在为应用程序提供配置数据的资源。最后，我们将介绍 Secrets，这是一种安全的方式，用于存储和提供敏感数据给在 Kubernetes 上运行的应用程序。总的来说，本章应该为您提供一个很好的工具集，用于在 Kubernetes 上配置生产应用程序。

在本章中，我们将涵盖以下主题：

+   使用最佳实践配置容器化应用程序

+   实施 ConfigMaps

+   使用 Secrets

# 技术要求

为了运行本章详细介绍的命令，您需要一台支持`kubectl`命令行工具的计算机，以及一个正常运行的 Kubernetes 集群。请查看*第一章*，*与 Kubernetes 通信*，以找到快速启动和运行 Kubernetes 的几种方法，并获取有关如何安装`kubectl`工具的说明。

本章中使用的代码可以在书籍的 GitHub 存储库中找到，网址为[`github.com/PacktPublishing/Cloud-Native-with-Kubernetes/tree/master/Chapter6`](https://github.com/PacktPublishing/Cloud-Native-with-Kubernetes/tree/master/Chapter6)。

# 使用最佳实践配置容器化应用程序

到目前为止，我们知道如何有效地部署（如*第四章*中所述，*扩展和部署您的应用程序*）和暴露（如*第五章*中所述，*服务和入口* - *与外部世界通信*）Kubernetes 上的容器化应用程序。这已足以在 Kubernetes 上运行非平凡的无状态容器化应用程序。然而，Kubernetes 还提供了用于应用程序配置和 Secrets 管理的额外工具。

由于 Kubernetes 运行容器，您始终可以配置应用程序以使用嵌入到 Dockerfile 中的环境变量。但这有些绕过了像 Kubernetes 这样的编排器的一些真正价值。我们希望能够在不重建 Docker 镜像的情况下更改我们的应用程序容器。为此，Kubernetes 为我们提供了两个以配置为重点的资源：ConfigMaps 和 Secrets。让我们首先看一下 ConfigMaps。

## 理解 ConfigMaps

在生产环境中运行应用程序时，开发人员希望能够快速、轻松地注入应用程序配置信息。有许多模式可以做到这一点 - 从使用查询的单独配置服务器，到使用环境变量或环境文件。这些策略在提供的安全性和可用性上有所不同。

对于容器化应用程序来说，环境变量通常是最简单的方法 - 但以安全的方式注入这些变量可能需要额外的工具或脚本。在 Kubernetes 中，ConfigMap 资源让我们以灵活、简单的方式做到这一点。ConfigMaps 允许 Kubernetes 管理员指定和注入配置信息，可以是文件或环境变量。

对于诸如秘密密钥之类的高度敏感信息，Kubernetes 为我们提供了另一个类似的资源 - Secrets。

## 理解 Secrets

Secrets 指的是需要以稍微更安全的方式存储的额外应用程序配置项 - 例如，受限 API 的主密钥、数据库密码等。Kubernetes 提供了一个称为 Secret 的资源，以编码方式存储应用程序配置信息。这并不会本质上使 Secret 更安全，但 Kubernetes 通过不自动在`kubectl get`或`kubectl describe`命令中打印秘密信息来尊重秘密的概念。这可以防止秘密意外打印到日志中。

为了确保 Secrets 实际上是秘密的，必须在集群上启用对秘密数据的静态加密 - 我们将在本章后面讨论如何做到这一点。从 Kubernetes 1.13 开始，这个功能让 Kubernetes 管理员可以防止 Secrets 未加密地存储在`etcd`中，并限制对`etcd`管理员的访问。

在我们深入讨论 Secrets 之前，让我们先讨论一下 ConfigMaps，它们更适合非敏感信息。

# 实施 ConfigMaps

ConfigMaps 为在 Kubernetes 上运行的容器存储和注入应用程序配置数据提供了一种简单的方式。

创建 ConfigMap 很简单 - 它们可以实现两种注入应用程序配置数据的可能性：

+   作为环境变量注入

+   作为文件注入

虽然第一种选项仅仅是在内存中使用容器环境变量，但后一种选项涉及到一些卷的方面 - 一种 Kubernetes 存储介质，将在下一章中介绍。我们现在将简要回顾一下，并将其用作卷的介绍，这将在下一章*第七章*中进行扩展，*Kubernetes 上的存储*。

在处理 ConfigMaps 时，使用命令式的`Kubectl`命令创建它们可能更容易。创建 ConfigMaps 的方法有几种，这也导致了从 ConfigMap 本身存储和访问数据的方式上的差异。第一种方法是简单地从文本值创建它，接下来我们将看到。

## 从文本值

通过命令从文本值创建 ConfigMap 的方法如下：

```
kubectl create configmap myapp-config --from-literal=mycategory.mykey=myvalue 
```

上一个命令创建了一个名为`myapp-config`的`configmap`，其中包含一个名为`mycategory.mykey`的键，其值为`myvalue`。您也可以创建一个具有多个键和值的 ConfigMap，如下所示：

```
kubectl create configmap myapp-config2 --from-literal=mycategory.mykey=myvalue
--from-literal=mycategory.mykey2=myvalue2 
```

上述命令会在`data`部分中生成一个具有两个值的 ConfigMap。

要查看您的 ConfigMap 的样子，请运行以下命令：

```
kubectl get configmap myapp-config2
```

您将看到以下输出：

configmap-output.yaml

```
apiVersion: v1
kind: ConfigMap
metadata:
  name: myapp-config2
  namespace: default
data:
  mycategory.mykey: myvalue
  mycategory.mykey2: myvalue2
```

当您的 ConfigMap 数据很长时，直接从文本值创建它就没有太多意义。对于更长的配置，我们可以从文件创建我们的 ConfigMap。

## 从文件

为了更容易创建一个具有许多不同值的 ConfigMap，或者重用您已经拥有的环境文件，您可以按照以下步骤从文件创建一个 ConfigMap：

1.  让我们从创建我们的文件开始，我们将把它命名为`env.properties`：

```
myconfigid=1125
publicapikey=i38ahsjh2
```

1.  然后，我们可以通过运行以下命令来创建我们的 ConfigMap：

```
kubectl create configmap my-config-map --from-file=env.properties
```

1.  要检查我们的`kubectl create`命令是否正确创建了 ConfigMap，让我们使用`kubectl describe`来描述它：

```
kubectl describe configmaps my-config-map
```

这应该会产生以下输出：

```
Name:           my-config-map
Namespace:      default
Labels:         <none>
Annotations:    <none>
Data
====
env.properties:        39 bytes
```

正如你所看到的，这个 ConfigMap 包含了我们的文本文件（以及字节数）。在这种情况下，我们的文件可以是任何文本文件 - 但是如果你知道你的文件被格式化为环境文件，你可以让 Kubernetes 知道这一点，以便让你的 ConfigMap 更容易阅读。让我们学习如何做到这一点。

## 从环境文件

如果我们知道我们的文件格式化为普通的环境文件与键值对，我们可以使用稍微不同的方法来创建我们的 ConfigMap-环境文件方法。这种方法将使我们的数据在 ConfigMap 对象中更加明显，而不是隐藏在文件中。

让我们使用与之前相同的文件进行环境特定的创建：

```
kubectl create configmap my-env-config-map --from-env-file=env.properties
```

现在，让我们使用以下命令描述我们的 ConfigMap：

```
> kubectl describe configmaps my-env-config-map
```

我们得到以下输出：

```
Name:         my-env-config-map
Namespace:    default
Labels:       <none>
Annotations:  <none>
Data
====
myconfigid:
----
1125
publicapikey:
----
i38ahsjh2
Events:  <none>
```

如您所见，通过使用`-from-env-file`方法，当您运行`kubectl describe`时，`env`文件中的数据很容易查看。这也意味着我们可以直接将我们的 ConfigMap 挂载为环境变量-稍后会详细介绍。

## 将 ConfigMap 挂载为卷

要在 Pod 中使用 ConfigMap 中的数据，您需要在规范中将其挂载到 Pod 中。这与在 Kubernetes 中挂载卷的方式非常相似（出于很好的原因，我们将会发现），卷是提供存储的资源。但是现在，不要担心卷。

让我们来看看我们的 Pod 规范，它将我们的`my-config-map` ConfigMap 作为卷挂载到我们的 Pod 上：

pod-mounting-cm.yaml

```
apiVersion: v1
kind: Pod
metadata:
  name: my-pod-mount-cm
spec:
  containers:
    - name: busybox
      image: busybox
      command:
      - sleep
      - "3600"
      volumeMounts:
      - name: my-config-volume
        mountPath: /app/config
  volumes:
    - name: my-config-volume
      configMap:
        name: my-config-map
  restartPolicy: Never
```

如您所见，我们的`my-config-map` ConfigMap 被挂载为卷（`my-config-volume`）在`/app/config`路径上，以便我们的容器访问。我们将在下一章关于存储中更多了解这是如何工作的。

在某些情况下，您可能希望将 ConfigMap 挂载为容器中的环境变量-我们将在下面学习如何做到这一点。

## 将 ConfigMap 挂载为环境变量

您还可以将 ConfigMap 挂载为环境变量。这个过程与将 ConfigMap 挂载为卷非常相似。

让我们来看看我们的 Pod 规范：

pod-mounting-cm-as-env.yaml

```
apiVersion: v1
kind: Pod
metadata:
  name: my-pod-mount-env
spec:
  containers:
    - name: busybox
      image: busybox
      command:
      - sleep
      - "3600"
      env:
        - name: MY_ENV_VAR
          valueFrom:
            configMapKeyRef:
              name: my-env-config-map
              key: myconfigid
  restartPolicy: Never
```

正如您所看到的，我们不是将 ConfigMap 作为卷挂载，而是在容器环境变量`MY_ENV_VAR`中引用它。为了做到这一点，我们需要在`valueFrom`键中使用`configMapRef`，并引用我们的 ConfigMap 的名称以及 ConfigMap 本身内部要查看的键。

正如我们在*使用最佳实践配置容器化应用程序*部分的章节开头提到的，ConfigMaps 默认情况下不安全，它们的数据以明文存储。为了增加一层安全性，我们可以使用 Secrets 而不是 ConfigMaps。

# 使用 Secrets

Secrets 与 ConfigMaps 非常相似，不同之处在于它们以编码文本（具体来说是 Base64）而不是明文存储。

因此，创建秘密与创建 ConfigMap 非常相似，但有一些关键区别。首先，通过命令方式创建秘密将自动对秘密中的数据进行 Base64 编码。首先，让我们看看如何从一对文件中命令方式创建秘密。

## 从文件

首先，让我们尝试从文件创建一个秘密（这也适用于多个文件）。我们可以使用`kubectl create`命令来做到这一点：

```
> echo -n 'mysecretpassword' > ./pass.txt
> kubectl create secret generic my-secret --from-file=./pass.txt
```

这应该会产生以下输出：

```
secret "my-secret" created
```

现在，让我们使用`kubectl describe`来查看我们的秘密是什么样子的：

```
> kubectl describe secrets/db-user-pass
```

这个命令应该会产生以下输出：

```
Name:            my-secret
Namespace:       default
Labels:          <none>
Annotations:     <none>
Type:            Opaque
Data
====
pass.txt:    16 bytes
```

正如您所看到的，`describe`命令显示了秘密中包含的字节数，以及它的类型`Opaque`。

创建秘密的另一种方法是使用声明性方法手动创建它。让我们看看如何做到这一点。

## 手动声明性方法

当从 YAML 文件声明性地创建秘密时，您需要使用编码实用程序预先对要存储的数据进行编码，例如 Linux 上的`base64`管道。

让我们在这里使用 Linux 的`base64`命令对我们的密码进行编码：

```
> echo -n 'myverybadpassword' | base64
bXl2ZXJ5YmFkcGFzc3dvcmQ=
```

现在，我们可以使用 Kubernetes YAML 规范声明性地创建我们的秘密，我们可以将其命名为`secret.yaml`：

```
apiVersion: v1
kind: Secret
metadata:
  name: my-secret
type: Opaque
data:
  dbpass: bXl2ZXJ5YmFkcGFzc3dvcmQ=
```

我们的`secret.yaml`规范包含我们创建的 Base64 编码字符串。

要创建秘密，请运行以下命令：

```
kubectl create -f secret.yaml
```

现在您知道如何创建秘密了。接下来，让我们学习如何挂载一个秘密供 Pod 使用。

## 将秘密挂载为卷

挂载秘密与挂载 ConfigMaps 非常相似。首先，让我们看看如何将秘密挂载到 Pod 作为卷（文件）。

让我们来看看我们的 Pod 规范。在这种情况下，我们正在运行一个示例应用程序，以便测试我们的秘密。以下是 YAML：

pod-mounting-secret.yaml

```
apiVersion: v1
kind: Pod
metadata:
  name: my-pod-mount-cm
spec:
  containers:
    - name: busybox
      image: busybox
      command:
      - sleep
      - "3600"
      volumeMounts:
      - name: my-config-volume
        mountPath: /app/config
        readOnly: true
  volumes:
    - name: foo
      secret:
      secretName: my-secret
  restartPolicy: Never
```

与 ConfigMap 的一个区别是，我们在卷上指定了`readOnly`，以防止在 Pod 运行时对秘密进行任何更改。在其他方面，我们挂载秘密的方式与 ConfigMap 相同。

接下来，我们将在下一章[*第七章*]（B14790_07_Final_PG_ePub.xhtml#_idTextAnchor166）*Kubernetes 上的存储*中深入讨论卷。但简单解释一下，卷是一种向 Pod 添加存储的方式。在这个例子中，我们挂载了我们的卷，你可以把它看作是一个文件系统，到我们的 Pod 上。然后我们的秘密被创建为文件系统中的一个文件。

## 将秘密挂载为环境变量

类似于文件挂载，我们可以以与 ConfigMap 挂载方式相同的方式将我们的秘密作为环境变量挂载。

让我们看一下另一个 Pod YAML。在这种情况下，我们将我们的 Secret 作为环境变量挂载：

pod-mounting-secret-env.yaml

```
apiVersion: v1
kind: Pod
metadata:
  name: my-pod-mount-env
spec:
  containers:
    - name: busybox
      image: busybox
      command:
      - sleep
      - "3600"
      env:
        - name: MY_PASSWORD_VARIABLE
          valueFrom:
            secretKeyRef:
              name: my-secret
              key: dbpass
  restartPolicy: Never
```

在使用`kubectl apply`创建前面的 Pod 后，让我们运行一个命令来查看我们的 Pod，看看变量是否被正确初始化。这与`docker exec`的方式完全相同：

```
> kubectl exec -it my-pod-mount-env -- /bin/bash
> printenv MY_PASSWORD_VARIABLE
myverybadpassword
```

它奏效了！现在您应该对如何创建，挂载和使用 ConfigMaps 和 Secrets 有了很好的理解。

作为关于 Secrets 的最后一个主题，我们将学习如何使用 Kubernetes `EncryptionConfig`创建安全的加密 Secrets。

## 实施加密的 Secrets

一些托管的 Kubernetes 服务（包括亚马逊的**弹性 Kubernetes 服务**（**EKS**））会自动加密`etcd`数据在静止状态下-因此您无需执行任何操作即可实现加密的 Secrets。像 Kops 这样的集群提供者有一个简单的标志（例如`encryptionConfig: true`）。但是，如果您是*以困难的方式*创建集群，您需要使用一个标志`--encryption-provider-config`和一个`EncryptionConfig`文件启动 Kubernetes API 服务器。

重要提示

从头开始创建一个完整的集群超出了本书的范围（请参阅*Kubernetes The Hard Way*，了解更多信息，网址为[`github.com/kelseyhightower/kubernetes-the-hard-way`](https://github.com/kelseyhightower/kubernetes-the-hard-way)）。

要快速了解加密是如何处理的，请查看以下`EncryptionConfiguration` YAML，它在启动时传递给`kube-apiserver`：

encryption-config.yaml

```
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
    - secrets
    providers:
    - aesgcm:
        keys:
        - name: key1
          secret: c2VjcmV0IGlzIHNlY3VyZQ==
        - name: key2
          secret: dGhpcyBpcyBwYXNzd29yZA==
```

前面的`EncryptionConfiguration` YAML 列出了应在`etcd`中加密的资源列表，以及可用于加密数据的一个或多个提供程序。截至 Kubernetes `1.17`，允许以下提供程序：

+   身份：无加密。

+   Aescbc：推荐的加密提供程序。

+   秘密盒：比 Aescbc 更快，更新。

+   Aesgcm：请注意，您需要自己实现 Aesgcm 的密钥轮换。

+   Kms：与第三方 Secrets 存储一起使用，例如 Vault 或 AWS KMS。

要查看完整列表，请参阅 https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/#providers。当列表中添加多个提供程序时，Kubernetes 将使用第一个配置的提供程序来加密对象。在解密时，Kubernetes 将按列表顺序进行解密尝试-如果没有一个有效，它将返回错误。

一旦我们创建了一个秘密（查看我们以前的任何示例如何做到这一点），并且我们的`EncryptionConfig`是活动的，我们可以检查我们的秘密是否实际上是加密的。

## 检查您的秘密是否已加密

检查您的秘密是否实际上在`etcd`中被加密的最简单方法是直接从`etcd`中获取值并检查加密前缀：

1.  首先，让我们使用`base64`创建一个秘密密钥：

```
> echo -n 'secrettotest' | base64
c2VjcmV0dG90ZXN0
```

1.  创建一个名为`secret_to_test.yaml`的文件，其中包含以下内容：

```
apiVersion: v1
kind: Secret
metadata:
 name: secret-to-test
type: Opaque
data:
  myencsecret: c2VjcmV0dG90ZXN0
```

1.  创建秘密：

```
kubectl apply -f secret_to_test.yaml
```

1.  创建了我们的秘密后，让我们检查它是否在`etcd`中被加密，通过直接查询它。您通常不需要经常直接查询`etcd`，但如果您可以访问用于引导集群的证书，这是一个简单的过程：

```
> export ETCDCTL_API=3 
> etcdctl --cacert=/etc/kubernetes/certs/ca.crt 
--cert=/etc/kubernetes/certs/etcdclient.crt 
--key=/etc/kubernetes/certs/etcdclient.key 
get /registry/secrets/default/secret-to-test
```

根据您配置的加密提供程序，您的秘密数据将以提供程序标记开头。例如，使用 Azure KMS 提供程序加密的秘密将以`k8s:enc:kms:v1:azurekmsprovider`开头。

1.  现在，通过`kubectl`检查秘密是否被正确解密（它仍然会被编码）：

```
> kubectl get secrets secret-to-test -o yaml
```

输出应该是`myencsecret: c2VjcmV0dG90ZXN0`，这是我们未加密的编码的秘密值：

```
> echo 'c2VjcmV0dG90ZXN0' | base64 --decode
> secrettotest
```

成功！

我们现在在我们的集群上运行加密。让我们找出如何删除它。

## 禁用集群加密

我们也可以相当容易地从我们的 Kubernetes 资源中删除加密。

首先，我们需要使用空白的加密配置 YAML 重新启动 Kubernetes API 服务器。如果您自行配置了集群，这应该很容易，但在 EKS 或 AKS 上，这是不可能手动完成的。您需要按照云提供商的具体文档来了解如何禁用加密。

如果您自行配置了集群或使用了诸如 Kops 或 Kubeadm 之类的工具，那么您可以使用以下`EncryptionConfiguration`在所有主节点上重新启动您的`kube-apiserver`进程：

encryption-reset.yaml

```
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
    - secrets
    providers:
    - identity: {}
```

重要提示

请注意，身份提供者不需要是唯一列出的提供者，但它需要是第一个，因为正如我们之前提到的，Kubernetes 使用第一个提供者来加密`etcd`中的新/更新对象。

现在，我们将手动重新创建所有我们的秘密，此时它们将自动使用身份提供者（未加密）：

```
kubectl get secrets --all-namespaces -o json | kubectl replace -f -
```

此时，我们所有的秘密都是未加密的！

# 摘要

在本章中，我们看了 Kubernetes 提供的注入应用程序配置的方法。首先，我们看了一些配置容器化应用程序的最佳实践。然后，我们回顾了 Kubernetes 提供的第一种方法，ConfigMaps，以及创建和挂载它们到 Pod 的几个选项。最后，我们看了一下 Secrets，当它们被加密时，是处理敏感配置的更安全的方式。到目前为止，您应该已经掌握了为应用程序提供安全和不安全配置值所需的所有工具。

在下一章中，我们将深入探讨一个我们已经涉及到的主题，即挂载我们的 Secrets 和 ConfigMaps - Kubernetes 卷资源，以及更一般地说，Kubernetes 上的存储。

# 问题

1.  Secrets 和 ConfigMaps 之间有什么区别？

1.  Secrets 是如何编码的？

1.  从常规文件创建 ConfigMap 和从环境文件创建 ConfigMap 之间的主要区别是什么？

1.  如何在 Kubernetes 上确保 Secrets 的安全？为什么它们不是默认安全的？

# 进一步阅读

+   有关 Kubernetes 数据加密配置的信息可以在官方文档中找到[`kubernetes.io/docs/tasks/administer-cluster/encrypt-data/`](https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/)。


# 第七章：Kubernetes 上的存储

在本章中，我们将学习如何在 Kubernetes 上提供应用程序存储。我们将回顾 Kubernetes 上的两种存储资源，即卷和持久卷。卷非常适合临时数据需求，但持久卷对于在 Kubernetes 上运行任何严肃的有状态工作负载是必不可少的。通过本章学到的技能，您将能够在多种不同的方式和环境中为在 Kubernetes 上运行的应用程序配置存储。

在本章中，我们将涵盖以下主题：

+   理解卷和持久卷之间的区别

+   使用卷

+   创建持久卷

+   持久卷索赔

# 技术要求

为了运行本章中详细介绍的命令，您需要一台支持`kubectl`命令行工具的计算机，以及一个可用的 Kubernetes 集群。请参阅*第一章*，*与 Kubernetes 通信*，了解快速启动和运行 Kubernetes 的几种方法，以及如何安装`kubectl`工具的说明。

本章中使用的代码可以在书籍的 GitHub 存储库中找到：[`github.com/PacktPublishing/Cloud-Native-with-Kubernetes/tree/master/Chapter7`](https://github.com/PacktPublishing/Cloud-Native-with-Kubernetes/tree/master/Chapter7)。

# 理解卷和持久卷之间的区别

一个完全无状态的容器化应用可能只需要磁盘空间来存储容器文件本身。在运行这种类型的应用程序时，Kubernetes 不需要额外的配置。

然而，在现实世界中，这并不总是正确的。正在转移到容器中的传统应用程序可能出于许多可能的原因需要磁盘空间卷。为了保存容器使用的文件，您需要 Kubernetes 卷资源。

Kubernetes 中可以创建两种主要存储资源：

+   卷

+   持久卷

两者之间的区别在于名称：虽然卷与特定 Pod 的生命周期相关联，但持久卷会一直保持活动状态，直到被删除，并且可以在不同的 Pod 之间共享。卷可以在 Pod 内部的容器之间共享数据，而持久卷可以用于许多可能的高级目的。

让我们先看看如何实现卷。

# 卷

Kubernetes 支持许多不同类型的卷。大多数可以用于卷或持久卷，但有些是特定于资源的。我们将从最简单的开始，然后回顾一些类型。

重要提示

您可以在 https://kubernetes.io/docs/concepts/storage/volumes/#types-of-volumes 上查看完整的当前卷类型列表。

以下是卷子类型的简短列表：

+   `awsElasticBlockStore`

+   `cephfs`

+   `ConfigMap`

+   `emptyDir`

+   `hostPath`

+   `local`

+   `nfs`

+   `persistentVolumeClaim`

+   `rbd`

+   `Secret`

正如您所看到的，ConfigMaps 和 Secrets 实际上是卷的*类型*。此外，列表包括云提供商卷类型，如`awsElasticBlockStore`。

与持久卷不同，持久卷是单独从任何一个 Pod 创建的，创建卷通常是在 Pod 的上下文中完成的。

要创建一个简单的卷，可以使用以下 Pod YAML：

pod-with-vol.yaml

```
apiVersion: v1
kind: Pod
metadata:
  name: pod-with-vol
spec:
  containers:
  - name: busybox
    image: busybox
    volumeMounts:
    - name: my-storage-volume
      mountPath: /data
  volumes:
  - name: my-storage-volume
    emptyDir: {}
```

这个 YAML 将创建一个带有`emptyDir`类型卷的 Pod。`emptyDir`类型的卷是使用分配给 Pod 的节点上已经存在的存储来配置的。如前所述，卷与 Pod 的生命周期相关，而不是与其容器相关。

这意味着在具有多个容器的 Pod 中，所有容器都将能够访问卷数据。让我们看一个 Pod 的以下示例 YAML 文件：

pod-with-multiple-containers.yaml

```
apiVersion: v1
kind: Pod
metadata:
  name: my-pod
spec:
  containers:
  - name: busybox
    image: busybox
    volumeMounts:
    - name: config-volume
      mountPath: /shared-config
  - name: busybox2
    image: busybox
    volumeMounts:
    - name: config-volume
      mountPath: /myconfig
  volumes:
  - name: config-volume
    emptyDir: {}
```

在这个例子中，Pod 中的两个容器都可以访问卷数据，尽管路径不同。容器甚至可以通过共享卷中的文件进行通信。

规范的重要部分是`volume spec`本身（`volumes`下的列表项）和卷的`mount`（`volumeMounts`下的列表项）。

每个挂载项都包含一个名称，对应于`volumes`部分中卷的名称，以及一个`mountPath`，它将决定卷被挂载到容器上的哪个文件路径。例如，在前面的 YAML 中，卷`config-volume`将在`busybox` Pod 中的`/shared-config`处访问，在`busybox2` Pod 中的`/myconfig`处访问。

卷规范本身需要一个名称 - 在本例中是`my-storage`，以及特定于卷类型的其他键/值，本例中是`emptyDir`，只需要空括号。

现在，让我们来看一个云配置卷挂载到 Pod 的例子。例如，要挂载 AWS **弹性块存储**（**EBS**）卷，可以使用以下 YAML：

pod-with-ebs.yaml

```
apiVersion: v1
kind: Pod
metadata:
  name: my-app
spec:
  containers:
  - image: busybox
    name: busybox
    volumeMounts:
    - mountPath: /data
      name: my-ebs-volume
  volumes:
  - name: my-ebs-volume
    awsElasticBlockStore:
      volumeID: [INSERT VOLUME ID HERE]
```

只要您的集群正确设置了与 AWS 的身份验证，此 YAML 将把现有的 EBS 卷附加到 Pod 上。正如您所看到的，我们使用`awsElasticBlockStore`键来专门配置要使用的确切卷 ID。在这种情况下，EBS 卷必须已经存在于您的 AWS 帐户和区域中。使用 AWS **弹性 Kubernetes 服务**（**EKS**）会更容易，因为它允许我们从 Kubernetes 内部自动提供 EBS 卷。

Kubernetes 还包括 Kubernetes AWS 云提供程序中的功能，用于自动提供卷-但这些是用于持久卷。我们将在*持久卷*部分看看如何获得这些自动提供的卷。

# 持久卷

持久卷相对于常规的 Kubernetes 卷具有一些关键优势。如前所述，它们（持久卷）的生命周期与集群的生命周期相关，而不是与单个 Pod 的生命周期相关。这意味着持久卷可以在集群运行时在 Pod 之间共享和重复使用。因此，这种模式更适合外部存储，比如 EBS（AWS 上的块存储服务），因为存储本身可以超过单个 Pod 的寿命。

实际上，使用持久卷需要两个资源：`PersistentVolume`本身和`PersistentVolumeClaim`，用于将`PersistentVolume`挂载到 Pod 上。

让我们从`PersistentVolume`本身开始-看一下创建`PersistentVolume`的基本 YAML：

pv.yaml

```
apiVersion: v1
kind: PersistentVolume
metadata:
  name: my-pv
spec:
  storageClassName: manual
  capacity:
    storage: 5Gi
  accessModes:
    - ReadWriteOnce
  hostPath:
    path: "/mnt/mydata"
```

现在让我们来分析一下。从规范中的第一行开始-`storageClassName`。

这个第一个配置，`storageClassName`，代表了我们想要使用的存储类型。对于`hostPath`卷类型，我们只需指定`manual`，但是对于 AWS EBS，例如，您可以创建并使用一个名为`gp2Encrypted`的存储类，以匹配 AWS 中的`gp2`存储类型，并启用 EBS 加密。因此，存储类是特定卷类型的可用配置的组合-可以在卷规范中引用。

继续使用我们的 AWS `StorageClass`示例，让我们为`gp2Encrypted`提供一个新的`StorageClass`：

gp2-storageclass.yaml

```
kind: StorageClass
apiVersion: storage.k8s.io/v1
metadata:
  name: gp2Encrypted
  annotations:
    storageclass.kubernetes.io/is-default-class: "true"
provisioner: kubernetes.io/aws-ebs
parameters:
  type: gp2
  encrypted: "true"
  fsType: ext4
```

现在，我们可以使用`gp2Encrypted`存储类创建我们的`PersistentVolume`。但是，使用动态配置的 EBS（或其他云）卷创建`PersistentVolumes`有一个快捷方式。当使用动态配置的卷时，我们首先创建`PersistentVolumeClaim`，然后自动生成`PersistentVolume`。

## 持久卷声明

现在我们知道您可以在 Kubernetes 中轻松创建持久卷，但是这并不允许您将存储绑定到 Pod。您需要创建一个`PersistentVolumeClaim`，它声明一个`PersistentVolume`并允许您将该声明绑定到一个或多个 Pod。

在上一节的新`StorageClass`的基础上，让我们创建一个声明，这将自动导致创建一个新的`PersistentVolume`，因为没有其他具有我们期望的`StorageClass`的持久卷：

pvc.yaml

```
kind: PersistentVolumeClaim
apiVersion: v1
metadata:
  name: my-pv-claim
spec:
  storageClassName: gp2Encrypted
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 1Gi
```

在这个文件上运行`kubectl apply -f`应该会导致创建一个新的自动生成的**持久卷**（**PV**）。如果您的 AWS 云服务提供商设置正确，这将导致创建一个新的类型为 GP2 且启用加密的 EBS 卷。

在将我们的基于 EBS 的持久卷附加到我们的 Pod 之前，让我们确认 EBS 卷在 AWS 中是否正确创建。

为此，我们可以转到 AWS 控制台，并确保我们在运行 EKS 集群的相同区域。然后转到**服务** > **EC2**，在**弹性块存储**下的左侧菜单中单击**卷**。在这一部分，我们应该看到一个与我们的 PVC 状态相同大小（**1 GiB**）的自动生成卷的项目。它应该具有 GP2 的类，并且应该启用加密。让我们看看这在 AWS 控制台中会是什么样子：

![图 7.1 - AWS 控制台自动生成的 EBS 卷](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cld-ntv-k8s/img/B14790_07_001.jpg)

图 7.1 - AWS 控制台自动生成的 EBS 卷

正如您所看到的，我们在 AWS 中正确地创建了我们动态生成的启用加密和分配**gp2**卷类型的 EBS 卷。现在我们已经创建了我们的卷，并且确认它已经在 AWS 中创建，我们可以将它附加到我们的 Pod 上。

## 将持久卷声明（PVC）附加到 Pods

现在我们既有了`PersistentVolume`又有了`PersistentVolumeClaim`，我们可以将它们附加到一个 Pod 以供使用。这个过程与附加 ConfigMap 或 Secret 非常相似 - 这是有道理的，因为 ConfigMaps 和 Secrets 本质上是卷的类型！

查看允许我们将加密的 EBS 卷附加到 Pod 并命名为`pod-with-attachment.yaml`的 YAML：

Pod-with-attachment.yaml

```
apiVersion: v1
kind: Pod
metadata:
  name: my-pod
spec:
  volumes:
    - name: my-pv
      persistentVolumeClaim:
        claimName: my-pv-claim
  containers:
    - name: my-container
      image: busybox
      volumeMounts:
        - mountPath: "/usr/data"
          name: my-pv
```

运行`kubectl apply -f pod-with-attachment.yaml`将创建一个 Pod，该 Pod 通过我们的声明将我们的`PersistentVolume`挂载到`/usr/data`。

为了确认卷已成功创建，让我们`exec`到我们的 Pod 中，并在我们的卷被挂载的位置创建一个文件：

```
> kubectl exec -it shell-demo -- /bin/bash
> cd /usr/data
> touch myfile.txt
```

现在，让我们使用以下命令删除 Pod：

```
> kubectl delete pod my-pod
```

然后使用以下命令再次重新创建它：

```
> kubectl apply -f my-pod.yaml
```

如果我们做得对，当再次运行`kubectl exec`进入 Pod 时，我们应该能够看到我们的文件：

```
> kubectl exec -it my-pod -- /bin/bash
> ls /usr/data
> myfile.txt
```

成功！

我们现在知道如何为 Kubernetes 创建由云存储提供的持久卷。但是，您可能正在本地环境或使用 minikube 在笔记本电脑上运行 Kubernetes。让我们看看您可以使用的一些替代持久卷子类型。

# 没有云存储的持久卷

我们之前的示例假设您正在云环境中运行 Kubernetes，并且可以使用云平台提供的存储服务（如 AWS EBS 和其他服务）。然而，这并非总是可能的。您可能正在数据中心环境中运行 Kubernetes，或者在专用硬件上运行。

在这种情况下，有许多潜在的解决方案可以为 Kubernetes 提供存储。一个简单的解决方案是将卷类型更改为`hostPath`，它可以在节点现有的存储设备中创建持久卷。例如，在 minikube 上运行时非常适用，但是不像 AWS EBS 那样提供强大的抽象。对于具有类似云存储工具 EBS 的本地功能的工具，让我们看看如何使用 Rook 的 Ceph。有关完整的文档，请查看 Rook 文档（它也会教你 Ceph）[`rook.io/docs/rook/v1.3/ceph-quickstart.html`](https://rook.io/docs/rook/v1.3/ceph-quickstart.html)。

Rook 是一个流行的开源 Kubernetes 存储抽象层。它可以通过各种提供者（如 EdgeFS 和 NFS）提供持久卷。在这种情况下，我们将使用 Ceph，这是一个提供对象、块和文件存储的开源存储项目。为简单起见，我们将使用块模式。

在 Kubernetes 上安装 Rook 实际上非常简单。我们将带您从安装 Rook 到设置 Ceph 集群，最终在我们的集群上提供持久卷。

## 安装 Rook

我们将使用 Rook GitHub 存储库提供的典型 Rook 安装默认设置。这可能会根据用例进行高度定制，但将允许我们快速为我们的工作负载设置块存储。请参考以下步骤来完成这个过程：

1.  首先，让我们克隆 Rook 存储库：

```
> git clone --single-branch --branch master https://github.com/rook/rook.git
> cd cluster/examples/kubernetes/ceph
```

1.  我们的下一步是创建所有相关的 Kubernetes 资源，包括几个**自定义资源定义**（**CRDs**）。我们将在后面的章节中讨论这些，但现在，请将它们视为特定于 Rook 的新 Kubernetes 资源，而不是典型的 Pods、Services 等。要创建常见资源，请运行以下命令：

```
> kubectl apply -f ./common.yaml
```

1.  接下来，让我们启动我们的 Rook 操作员，它将处理为特定的 Rook 提供程序（在本例中将是 Ceph）提供所有必要资源的规划：

```
> kubectl apply -f ./operator.yaml
```

1.  在下一步之前，请确保 Rook 操作员 Pod 实际上正在运行，使用以下命令：

```
> kubectl -n rook-ceph get pod
```

1.  一旦 Rook Pod 处于“运行”状态，我们就可以设置我们的 Ceph 集群！此 YAML 也在我们从 Git 克隆的文件夹中。使用以下命令创建它：

```
> kubectl create -f cluster.yaml
```

这个过程可能需要几分钟。Ceph 集群由几种不同的 Pod 类型组成，包括操作员、**对象存储设备**（**OSDs**）和管理器。

为了确保我们的 Ceph 集群正常工作，Rook 提供了一个工具箱容器映像，允许您使用 Rook 和 Ceph 命令行工具。要启动工具箱，您可以使用 Rook 项目提供的工具箱 Pod 规范，网址为[`rook.io/docs/rook/v0.7/toolbox.html`](https://rook.io/docs/rook/v0.7/toolbox.html)。

这是工具箱 Pod 的规范示例：

rook-toolbox-pod.yaml

```
apiVersion: v1
kind: Pod
metadata:
  name: rook-tools
  namespace: rook
spec:
  dnsPolicy: ClusterFirstWithHostNet
  containers:
  - name: rook-tools
    image: rook/toolbox:v0.7.1
    imagePullPolicy: IfNotPresent
```

正如您所看到的，这个 Pod 使用了 Rook 提供的特殊容器映像。该映像预装了您需要调查 Rook 和 Ceph 的所有工具。

一旦您的工具箱 Pod 运行起来，您可以使用`rookctl`和`ceph`命令来检查集群状态（查看 Rook 文档以获取具体信息）。

## rook-ceph-block 存储类

现在我们的集群正在运行，我们可以创建将被 PVs 使用的存储类。我们将称这个存储类为`rook-ceph-block`。这是我们的 YAML 文件（`ceph-rook-combined.yaml`），其中将包括我们的`CephBlockPool`（它将处理 Ceph 中的块存储 - 有关更多信息，请参阅[`rook.io/docs/rook/v0.9/ceph-pool-crd.html`](https://rook.io/docs/rook/v0.9/ceph-pool-crd.html)）以及存储类本身：

ceph-rook-combined.yaml

```
apiVersion: ceph.rook.io/v1
kind: CephBlockPool
metadata:
  name: replicapool
  namespace: rook-ceph
spec:
  failureDomain: host
  replicated:
    size: 3
---
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
   name: rook-ceph-block
provisioner: rook-ceph.rbd.csi.ceph.com
parameters:
    clusterID: rook-ceph
    pool: replicapool
    imageFormat: "2"
currently supports only `layering` feature.
    imageFeatures: layering
    csi.storage.k8s.io/provisioner-secret-name: rook-csi-rbd-provisioner
    csi.storage.k8s.io/provisioner-secret-namespace: rook-ceph
    csi.storage.k8s.io/node-stage-secret-name: rook-csi-rbd-node
    csi.storage.k8s.io/node-stage-secret-namespace: rook-ceph
csi-provisioner
    csi.storage.k8s.io/fstype: xfs
reclaimPolicy: Delete
```

正如你所看到的，YAML 规范定义了我们的`StorageClass`和`CephBlockPool`资源。正如我们在本章前面提到的，`StorageClass`是我们告诉 Kubernetes 如何满足`PersistentVolumeClaim`的方式。另一方面，`CephBlockPool`资源告诉 Ceph 如何以及在哪里创建分布式存储资源-在这种情况下，要复制多少存储。

现在我们可以给我们的 Pod 一些存储了！让我们使用我们的新存储类创建一个新的 PVC：

rook-ceph-pvc.yaml

```
kind: PersistentVolumeClaim
apiVersion: v1
metadata:
  name: rook-pvc
spec:
  storageClassName: rook-ceph-block
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 1Gi
```

我们的 PVC 是存储类`rook-ceph-block`，因此它将使用我们刚刚创建的新存储类。现在，让我们在 YAML 文件中将 PVC 分配给我们的 Pod：

rook-ceph-pod.yaml

```
apiVersion: v1
kind: Pod
metadata:
  name: my-rook-test-pod
spec:
  volumes:
    - name: my-rook-pv
      persistentVolumeClaim:
        claimName: rook-pvc
  containers:
    - name: my-container
      image: busybox
      volumeMounts:
        - mountPath: "/usr/rooktest"
          name: my-rook-pv
```

当 Pod 被创建时，Rook 应该会启动一个新的持久卷并将其附加到 Pod 上。让我们查看一下 Pod，看看它是否正常工作：

```
> kubectl exec -it my-rook-test-pod -- /bin/bash
> cd /usr/rooktest
> touch myfile.txt
> ls
```

我们得到了以下输出：

```
> myfile.txt
```

成功！

尽管我们刚刚使用了 Ceph 的块存储功能，但它也有文件系统模式，这有一些好处-让我们讨论一下为什么你可能想要使用它。

## Rook Ceph 文件系统

Rook 的 Ceph 块提供程序的缺点是一次只能由一个 Pod 进行写入。为了使用 Rook/Ceph 创建一个`ReadWriteMany`持久卷，我们需要使用支持 RWX 模式的文件系统提供程序。有关更多信息，请查看 Rook/Ceph 文档[`rook.io/docs/rook/v1.3/ceph-quickstart.html`](https://rook.io/docs/rook/v1.3/ceph-quickstart.html)。

在创建 Ceph 集群之前，所有先前的步骤都适用。在这一点上，我们需要创建我们的文件系统。让我们使用以下的 YAML 文件来创建它：

rook-ceph-fs.yaml

```
apiVersion: ceph.rook.io/v1
kind: CephFilesystem
metadata:
  name: ceph-fs
  namespace: rook-ceph
spec:
  metadataPool:
    replicated:
      size: 2
  dataPools:
    - replicated:
        size: 2
  preservePoolsOnDelete: true
  metadataServer:
    activeCount: 1
    activeStandby: true
```

在这种情况下，我们正在复制元数据和数据到至少两个池，以确保可靠性，如在`metadataPool`和`dataPool`块中配置的那样。我们还使用`preservePoolsOnDelete`键在删除时保留池。

接下来，让我们为 Rook/Ceph 文件系统存储专门创建一个新的存储类。以下的 YAML 文件就是这样做的：

rook-ceph-fs-storageclass.yaml

```
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: rook-cephfs
provisioner: rook-ceph.cephfs.csi.ceph.com
parameters:
  clusterID: rook-ceph
  fsName: ceph-fs
  pool: ceph-fs-data0
  csi.storage.k8s.io/provisioner-secret-name: rook-csi-cephfs-provisioner
  csi.storage.k8s.io/provisioner-secret-namespace: rook-ceph
  csi.storage.k8s.io/node-stage-secret-name: rook-csi-cephfs-node
  csi.storage.k8s.io/node-stage-secret-namespace: rook-ceph
reclaimPolicy: Delete
```

这个`rook-cephfs`存储类指定了我们之前创建的池，并描述了我们存储类的回收策略。最后，它使用了一些在 Rook/Ceph 文档中解释的注释。现在，我们可以通过 PVC 将其附加到一个部署中，而不仅仅是一个 Pod！看一下我们的 PV：

rook-cephfs-pvc.yaml

```
kind: PersistentVolumeClaim
apiVersion: v1
metadata:
  name: rook-ceph-pvc
spec:
  storageClassName: rook-cephfs
  accessModes:
    - ReadWriteMany
  resources:
    requests:
      storage: 1Gi
```

这个持久卷引用了我们的新的`rook-cephfs`存储类，使用`ReadWriteMany`模式 - 我们要求`1 Gi`的数据。接下来，我们可以创建我们的`Deployment`：

rook-cephfs-deployment.yaml

```
apiVersion: v1
kind: Deployment
metadata:
  name: my-rook-fs-test
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
      spec:
  	  volumes:
    	  - name: my-rook-ceph-pv
        persistentVolumeClaim:
          claimName: rook-ceph-pvc
  	  containers:
    	  - name: my-container
         image: busybox
         volumeMounts:
         - mountPath: "/usr/rooktest"
           name: my-rook-ceph-pv
```

这个`Deployment`引用了我们的`ReadWriteMany`持久卷声明，使用`volumes`下的`persistentVolumeClaim`块。部署后，我们所有的 Pod 现在都可以读写同一个持久卷。

之后，您应该对如何创建持久卷并将它们附加到 Pod 有很好的理解。

# 总结

在本章中，我们回顾了在 Kubernetes 上提供存储的两种方法 - 卷和持久卷。首先，我们讨论了这两种方法之间的区别：虽然卷与 Pod 的生命周期相关，但持久卷会持续到它们或集群被删除。然后，我们看了如何实现卷并将它们附加到我们的 Pod。最后，我们将我们对卷的学习扩展到持久卷，并发现了如何使用几种不同类型的持久卷。这些技能将帮助您在许多可能的环境中为您的应用分配持久和非持久的存储 - 从本地到云端。

在下一章中，我们将从应用程序关注点中脱离出来，讨论如何在 Kubernetes 上控制 Pod 的放置。

# 问题

1.  卷和持久卷之间有什么区别？

1.  什么是`StorageClass`，它与卷有什么关系？

1.  在创建 Kubernetes 资源（如持久卷）时，如何自动配置云资源？

1.  在哪些情况下，您认为使用卷而不是持久卷会是禁止的？

# 进一步阅读

请参考以下链接获取更多信息：

+   Rook 的 Ceph 存储快速入门：[`github.com/rook/rook/blob/master/Documentation/ceph-quickstart.md`](https://github.com/rook/rook/blob/master/Documentation/ceph-quickstart.md)

+   Rook 工具箱：[`rook.io/docs/rook/v0.7/toolbox.html`](https://rook.io/docs/rook/v0.7/toolbox.html)

+   云提供商：https://kubernetes.io/docs/tasks/administer-cluster/running-cloud-controller/


# 第八章：Pod 放置控制

本章描述了在 Kubernetes 中控制 Pod 放置的各种方式，以及解释为什么首先实施这些控制可能是一个好主意。Pod 放置意味着控制 Pod 在 Kubernetes 中被调度到哪个节点。我们从简单的控制开始，比如节点选择器，然后转向更复杂的工具，比如污点和容忍度，最后介绍两个 beta 功能，节点亲和性和 Pod 间亲和性/反亲和性。

在过去的章节中，我们已经学习了如何在 Kubernetes 上最好地运行应用程序 Pod - 从使用部署协调和扩展它们，使用 ConfigMaps 和 Secrets 注入配置，到使用持久卷添加存储。

然而，尽管如此，我们始终依赖 Kubernetes 调度程序将 Pod 放置在最佳节点上，而没有给调度程序提供有关所讨论的 Pod 的太多信息。到目前为止，我们已经在 Pod 中添加了资源限制和请求（Pod 规范中的`resource.requests`和`resource.limits`）。资源请求指定 Pod 在调度时需要的节点上的最低空闲资源水平，而资源限制指定 Pod 允许使用的最大资源量。然而，我们并没有对 Pod 必须运行在哪些节点或节点集上提出任何具体要求。

对于许多应用程序和集群来说，这是可以的。然而，正如我们将在第一节中看到的，有许多情况下使用更精细的 Pod 放置控制是一种有用的策略。

在本章中，我们将涵盖以下主题：

+   识别 Pod 放置的用例

+   使用节点选择器

+   实施污点和容忍度

+   使用节点亲和性控制 Pod

+   使用 Pod 亲和性和反亲和性

# 技术要求

为了运行本章中详细介绍的命令，您需要一台支持`kubectl`命令行工具的计算机，以及一个可用的 Kubernetes 集群。请参阅*第一章*，*与 Kubernetes 通信*，了解快速启动和运行 Kubernetes 的几种方法，以及如何安装`kubectl`工具的说明。

本章中使用的代码可以在书的 GitHub 存储库中找到[`github.com/PacktPublishing/Cloud-Native-with-Kubernetes/tree/master/Chapter8`](https://github.com/PacktPublishing/Cloud-Native-with-Kubernetes/tree/master/Chapter8)。

# 识别 Pod 放置的用例

Pod 放置控制是 Kubernetes 提供给我们的工具，用于决定将 Pod 调度到哪个节点，或者由于缺少我们想要的节点而完全阻止 Pod 的调度。这可以用于几种不同的模式，但我们将回顾一些主要的模式。首先，Kubernetes 本身默认完全实现了 Pod 放置控制-让我们看看如何实现。

## Kubernetes 节点健康放置控制

Kubernetes 使用一些默认的放置控制来指定某种方式不健康的节点。这些通常是使用污点和容忍来定义的，我们将在本章后面详细讨论。

Kubernetes 使用的一些默认污点（我们将在下一节中讨论）如下：

+   `memory-pressure`

+   `disk-pressure`

+   `unreachable`

+   `not-ready`

+   `out-of-disk`

+   `network-unavailable`

+   `unschedulable`

+   `uninitialized`（仅适用于由云提供商创建的节点）

这些条件可以将节点标记为无法接收新的 Pod，尽管调度器在处理这些污点的方式上有一定的灵活性，我们稍后会看到。这些系统创建的放置控制的目的是防止不健康的节点接收可能无法正常运行的工作负载。

除了用于节点健康的系统创建的放置控制之外，还有一些用例，您作为用户可能希望实现精细调度，我们将在下一节中看到。

## 需要不同节点类型的应用程序

在异构的 Kubernetes 集群中，每个节点并不相同。您可能有一些更强大的虚拟机（或裸金属）和一些较弱的，或者有不同的专门的节点集。

例如，在运行数据科学流水线的集群中，您可能有具有 GPU 加速能力的节点来运行深度学习算法，常规计算节点来提供应用程序，具有大量内存的节点来基于已完成的模型进行推理，等等。

使用 Pod 放置控制，您可以确保平台的各个部分在最适合当前任务的硬件上运行。

## 需要特定数据合规性的应用程序

与前面的例子类似，应用程序要求可能决定了对不同类型的计算需求，某些数据合规性需求可能需要特定类型的节点。

例如，像 AWS 和 Azure 这样的云提供商通常允许您购买具有专用租户的 VM - 这意味着没有其他应用程序在底层硬件和虚拟化程序上运行。这与其他典型的云提供商 VM 不同，其他客户可能共享单个物理机。

对于某些数据法规，需要这种专用租户级别来保持合规性。为了满足这种需求，您可以使用 Pod 放置控件来确保相关应用仅在具有专用租户的节点上运行，同时通过在更典型的 VM 上运行控制平面来降低成本。

## 多租户集群

如果您正在运行一个具有多个租户的集群（例如通过命名空间分隔），您可以使用 Pod 放置控件来为租户保留某些节点或节点组，以便将它们与集群中的其他租户物理或以其他方式分开。这类似于 AWS 或 Azure 中的专用硬件的概念。

## 多个故障域

尽管 Kubernetes 已经通过允许您在多个节点上运行工作负载来提供高可用性，但也可以扩展这种模式。我们可以创建自己的 Pod 调度策略，考虑跨多个节点的故障域。处理这个问题的一个很好的方法是通过 Pod 或节点的亲和性或反亲和性特性，我们将在本章后面讨论。

现在，让我们构想一个情况，我们的集群在裸机上，每个物理机架有 20 个节点。如果每个机架都有自己的专用电源连接和备份，它可以被视为一个故障域。当电源连接失败时，机架上的所有机器都会失败。因此，我们可能希望鼓励 Kubernetes 在不同的机架/故障域上运行两个实例或 Pod。以下图显示了应用程序如何跨故障域运行：

![图 8.1 - 故障域](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cld-ntv-k8s/img/B14790_08_001.jpg)

图 8.1 - 故障域

正如您在图中所看到的，由于应用程序 Pod 分布在多个故障域中，而不仅仅是在同一故障域中的多个节点，即使*故障域 1*发生故障，我们也可以保持正常运行。*App A - Pod 1*和*App B - Pod 1*位于同一个（红色）故障域。但是，如果该故障域（*Rack 1*）发生故障，我们仍将在*Rack 2*上有每个应用的副本。

我们在这里使用“鼓励”这个词，因为在 Kubernetes 调度程序中，可以将一些功能配置为硬性要求或尽力而为。

这些示例应该让您对高级放置控件的一些潜在用例有一个扎实的理解。

现在让我们讨论实际的实现，逐个使用每个放置工具集。我们将从最简单的节点选择器开始。

# 使用节点选择器和节点名称

节点选择器是 Kubernetes 中一种非常简单的放置控制类型。每个 Kubernetes 节点都可以在元数据块中带有一个或多个标签，并且 Pod 可以指定一个节点选择器。

要为现有节点打标签，您可以使用`kubectl label`命令：

```
> kubectl label nodes node1 cpu_speed=fast
```

在这个例子中，我们使用标签`cpu_speed`和值`fast`来标记我们的`node1`节点。

现在，让我们假设我们有一个应用程序，它确实需要快速的 CPU 周期才能有效地执行。我们可以为我们的工作负载添加`nodeSelector`，以确保它只被调度到具有我们快速 CPU 速度标签的节点上，如下面的代码片段所示：

pod-with-node-selector.yaml

```
apiVersion: v1
kind: Pod
metadata:
  name: speedy-app
spec:
  containers:
  - name: speedy-app
    image: speedy-app:latest
    imagePullPolicy: IfNotPresent
  nodeSelector:
    cpu_speed: fast
```

当部署时，作为部署的一部分或单独部署，我们的`speedy-app` Pod 将只被调度到具有`cpu_speed`标签的节点上。

请记住，与我们即将审查的一些其他更高级的 Pod 放置选项不同，节点选择器中没有任何余地。如果没有具有所需标签的节点，应用程序将根本不会被调度。

对于更简单（但更脆弱）的选择器，您可以使用`nodeName`，它指定 Pod 应该被调度到的确切节点。您可以像这样使用它：

pod-with-node-name.yaml

```
apiVersion: v1
kind: Pod
metadata:
  name: speedy-app
spec:
  containers:
  - name: speedy-app
    image: speedy-app:latest
    imagePullPolicy: IfNotPresent
  nodeName: node1
```

正如您所看到的，这个选择器只允许 Pod 被调度到`node1`，所以如果它当前由于任何原因不接受 Pods，Pod 将不会被调度。

对于稍微更加微妙的放置控制，让我们转向污点和容忍。

# 实施污点和容忍

在 Kubernetes 中，污点和容忍的工作方式类似于反向节点选择器。与节点吸引 Pods 因具有适当的标签而被选择器消耗不同，我们对节点进行污点处理，这会排斥所有 Pod 被调度到该节点，然后标记我们的 Pods 具有容忍，这允许它们被调度到被污点处理的节点上。

正如本章开头提到的，Kubernetes 使用系统创建的污点来标记节点为不健康，并阻止新的工作负载被调度到它们上面。例如，`out-of-disk`污点将阻止任何新的 Pod 被调度到具有该污点的节点上。

让我们使用污点和容忍度来应用与节点选择器相同的示例用例。由于这基本上是我们先前设置的反向，让我们首先使用`kubectl taint`命令给我们的节点添加一个污点：

```
> kubectl taint nodes node2 cpu_speed=slow:NoSchedule
```

让我们分解这个命令。我们给`node2`添加了一个名为`cpu_speed`的污点和一个值`slow`。我们还用一个效果标记了这个污点 - 在这种情况下是`NoSchedule`。

一旦我们完成了我们的示例（如果您正在跟随命令进行操作，请不要立即执行此操作），我们可以使用减号运算符删除`taint`：

```
> kubectl taint nodes node2 cpu_speed=slow:NoSchedule-
```

`taint`效果让我们在调度器处理污点时增加了一些细粒度。有三种可能的效果值：

+   `NoSchedule`

+   `NoExecute`

+   `PreferNoSchedule`

前两个效果，`NoSchedule`和`NoExecute`，提供了硬效果 - 也就是说，像节点选择器一样，只有两种可能性，要么 Pod 上存在容忍度（我们马上就会看到），要么 Pod 没有被调度。`NoExecute`通过驱逐所有具有容忍度的节点上的 Pod 来增加这个基本功能，而`NoSchedule`让现有的 Pod 保持原状，同时阻止任何没有容忍度的新 Pod 加入。

`PreferNoSchedule`，另一方面，为 Kubernetes 调度器提供了一些余地。它告诉调度器尝试为没有不可容忍污点的 Pod 找到一个节点，但如果不存在，则继续安排它。它实现了软效果。

在我们的情况下，我们选择了`NoSchedule`，因此不会将新的 Pod 分配给该节点 - 除非当然我们提供了一个容忍度。现在让我们这样做。假设我们有第二个应用程序，它不关心 CPU 时钟速度。它很乐意生活在我们较慢的节点上。这是 Pod 清单：

pod-without-speed-requirement.yaml

```
apiVersion: v1
kind: Pod
metadata:
  name: slow-app
spec:
  containers:
  - name: slow-app
    image: slow-app:latest
```

现在，我们的`slow-app` Pod 将不会在任何具有污点的节点上运行。我们需要为这个 Pod 提供一个容忍度，以便它可以被调度到具有污点的节点上 - 我们可以这样做：

pod-with-toleration.yaml

```
apiVersion: v1
kind: Pod
metadata:
  name: slow-app
spec:
  containers:
  - name: slow-app
    image: slow-app:latest
tolerations:
- key: "cpu_speed"
  operator: "Equal"
  value: "slow"
  effect: "NoSchedule"
```

让我们分解我们的`tolerations`条目，这是一个值数组。每个值都有一个`key`-与我们的污点名称相同。然后是一个`operator`值。这个`operator`可以是`Equal`或`Exists`。对于`Equal`，您可以使用`value`键，就像前面的代码中那样，配置污点必须等于的值，以便 Pod 容忍。对于`Exists`，污点名称必须在节点上，但不管值是什么都没有关系，就像这个 Pod 规范中一样：

pod-with-toleration2.yaml

```
apiVersion: v1
kind: Pod
metadata:
  name: slow-app
spec:
  containers:
  - name: slow-app
    image: slow-app:latest
tolerations:
- key: "cpu_speed"
  operator: "Exists"
  effect: "NoSchedule"
```

如您所见，我们已经使用了`Exists` `operator`值来允许我们的 Pod 容忍任何`cpu_speed`污点。

最后，我们有我们的`effect`，它的工作方式与污点本身的`effect`相同。它可以包含与污点效果完全相同的值- `NoSchedule`，`NoExecute`和`PreferNoSchedule`。

具有`NoExecute`容忍的 Pod 将无限期容忍与其关联的污点。但是，您可以添加一个名为`tolerationSeconds`的字段，以便在经过规定的时间后，Pod 离开受污染的节点。这允许您指定在一段时间后生效的容忍。让我们看一个例子：

pod-with-toleration3.yaml

```
apiVersion: v1
kind: Pod
metadata:
  name: slow-app
spec:
  containers:
  - name: slow-app
    image: slow-app:latest
tolerations:
- key: "cpu_speed"
  operator: "Equal"
  Value: "slow"
  effect: "NoExecute"
  tolerationSeconds: 60
```

在这种情况下，当污点和容忍执行时，已经在具有`taint`的节点上运行的 Pod 将在重新调度到不同节点之前在节点上保留`60`秒。

## 多个污点和容忍

当 Pod 和节点上有多个污点或容忍时，调度程序将检查它们所有。这里没有`OR`逻辑运算符-如果节点上的任何污点在 Pod 上没有匹配的容忍，它将不会被调度到节点上（除了`PreferNoSchedule`之外，在这种情况下，与以前一样，调度程序将尽量不在节点上调度）。即使在节点上有六个污点中，Pod 容忍了其中五个，它仍然不会被调度到`NoSchedule`污点，并且仍然会因为`NoExecute`污点而被驱逐。

对于一个可以更微妙地控制放置方式的工具，让我们看一下节点亲和力。

# 使用节点亲和力控制 Pod

正如你可能已经注意到的，污点和容忍性 - 虽然比节点选择器灵活得多 - 仍然留下了一些用例未解决，并且通常只允许*过滤*模式，你可以使用`Exists`或`Equals`来匹配特定的污点。可能有更高级的用例，你想要更灵活的方法来选择节点 - Kubernetes 的*亲和性*就是解决这个问题的功能。

有两种亲和性：

+   **节点亲和性**

+   **跨 Pod 的亲和性**

节点亲和性是节点选择器的类似概念，只是它允许更强大的选择特征集。让我们看一些示例 YAML，然后分解各个部分：

pod-with-node-affinity.yaml

```
apiVersion: v1
kind: Pod
metadata:
  name: affinity-test
spec:
  affinity:
    nodeAffinity:
      requiredDuringSchedulingIgnoredDuringExecution:
        nodeSelectorTerms:
        - matchExpressions:
          - key: cpu_speed
            operator: In
            values:
            - fast
            - medium_fast
  containers:
  - name: speedy-app
    image: speedy-app:latest
```

正如你所看到的，我们的`Pod` `spec`有一个`affinity`键，并且我们指定了一个`nodeAffinity`设置。有两种可能的节点亲和性类型：

+   `requiredDuringSchedulingIgnoredDuringExecution`

+   `preferredDuringSchedulingIgnoredDuringExecution`

这两种类型的功能直接映射到`NoSchedule`和`PreferNoSchedule`的工作方式。

## 使用 requiredDuringSchedulingIgnoredDuringExecution 节点亲和性

对于`requiredDuringSchedulingIgnoredDuringExecution`，Kubernetes 永远不会调度一个没有与节点匹配的术语的 Pod。

对于`preferredDuringSchedulingIgnoredDuringExecution`，它将尝试满足软性要求，但如果不能，它仍然会调度 Pod。

节点亲和性相对于节点选择器和污点和容忍性的真正能力在于你可以在选择器方面实现的实际表达式和逻辑。

`requiredDuringSchedulingIgnoredDuringExecution`和`preferredDuringSchedulingIgnoredDuringExecution`亲和性的功能是非常不同的，因此我们将分别进行审查。

对于我们的`required`亲和性，我们有能力指定`nodeSelectorTerms` - 可以是一个或多个包含`matchExpressions`的块。对于每个`matchExpressions`块，可以有多个表达式。

在我们在上一节中看到的代码块中，我们有一个单一的节点选择器术语，一个`matchExpressions`块 - 它本身只有一个表达式。这个表达式寻找`key`，就像节点选择器一样，代表一个节点标签。接下来，它有一个`operator`，它给了我们一些灵活性，让我们决定如何识别匹配。以下是操作符的可能值：

+   `In`

+   `NotIn`

+   `Exists`

+   `DoesNotExist`

+   `Gt`（注意：大于）

+   `Lt`（注意：小于）

在我们的情况下，我们使用了`In`运算符，它将检查值是否是我们指定的几个值之一。最后，在我们的`values`部分，我们可以列出一个或多个值，根据运算符，必须匹配才能使表达式为真。

正如你所看到的，这为我们在指定选择器时提供了更大的粒度。让我们看一个使用不同运算符的`cpu_speed`的例子：

pod-with-node-affinity2.yaml

```
apiVersion: v1
kind: Pod
metadata:
  name: affinity-test
spec:
  affinity:
    nodeAffinity:
      requiredDuringSchedulingIgnoredDuringExecution:
        nodeSelectorTerms:
        - matchExpressions:
          - key: cpu_speed
            operator: Gt
            values:
            - "5"
  containers:
  - name: speedy-app
    image: speedy-app:latest
```

正如你所看到的，我们正在使用非常精细的`matchExpressions`选择器。现在，使用更高级的运算符匹配的能力使我们能够确保我们的`speedy-app`只安排在具有足够高时钟速度（在本例中为 5 GHz）的节点上。我们可以更加精细地规定，而不是将我们的节点分类为“慢”和“快”这样的广泛组别。

接下来，让我们看看另一种节点亲和性类型 - `preferredDuringSchedulingIgnoredDuringExecution`。

## 使用 preferredDuringSchedulingIgnoredDuringExecution 节点亲和性

这种情况的语法略有不同，并且使我们能够更精细地影响这个“软”要求。让我们看一个实现这一点的 Pod spec YAML：

pod-with-node-affinity3.yaml

```
apiVersion: v1
kind: Pod
metadata:
  name: slow-app-affinity
spec:
  affinity:
    nodeAffinity:
      preferredDuringSchedulingIgnoredDuringExecution:
      - weight: 1
        preference:
          matchExpressions:
          - key: cpu_speed
            operator: Lt
            values:
            - "3"
  containers:
  - name: slow-app
    image: slow-app:latest
```

这看起来与我们的`required`语法有些不同。

对于`preferredDuringSchedulingIgnoredDuringExecution`，我们有能力为每个条目分配一个“权重”，并附带一个偏好，这可以再次是一个包含多个内部表达式的`matchExpressions`块，这些表达式使用相同的`key-operator-values`语法。

这里的关键区别是“权重”值。由于`preferredDuringSchedulingIgnoredDuringExecution`是一个**软**要求，我们可以列出几个不同的偏好，并附带权重，让调度器尽力满足它们。其工作原理是，调度器将遍历所有偏好，并根据每个偏好的权重和是否满足来计算节点的得分。假设所有硬性要求都得到满足，调度器将选择得分最高的节点。在前面的情况下，我们有一个权重为 1 的单个偏好，但权重可以从 1 到 100 不等 - 所以让我们看一个更复杂的设置，用于我们的`speedy-app`用例：

pod-with-node-affinity4.yaml

```
apiVersion: v1
kind: Pod
metadata:
  name: speedy-app-prefers-affinity
spec:
  affinity:
    nodeAffinity:
      preferredDuringSchedulingIgnoredDuringExecution:
      - weight: 90
        preference:
          matchExpressions:
          - key: cpu_speed
            operator: Gt
            values:
            - "3"
      - weight: 10
        preference:
          matchExpressions:
          - key: memory_speed
            operator: Gt
            values:
            - "4"
  containers:
  - name: speedy-app
    image: speedy-app:latest
```

在确保我们的`speedy-app`在最佳节点上运行的过程中，我们决定只实现`soft`要求。如果没有快速节点存在，我们仍希望我们的应用程序被调度和运行。为此，我们指定了两个偏好 - 一个`cpu_speed`超过 3（3 GHz）和一个内存速度超过 4（4 GHz）的节点。

由于我们的应用程序更多地受限于 CPU 而不是内存，我们决定适当地权衡我们的偏好。在这种情况下，`cpu_speed`具有`weight`为`90`，而`memory_speed`具有`weight`为`10`。

因此，满足我们的`cpu_speed`要求的任何节点的计算得分都比仅满足`memory_speed`要求的节点高得多 - 但仍然比同时满足两者的节点低。当我们尝试为这个应用程序调度 10 或 100 个新的 Pod 时，您可以看到这种计算是如何有价值的。

## 多个节点亲和性

当我们处理多个节点亲和性时，有一些关键的逻辑要记住。首先，即使只有一个节点亲和性，如果它与同一 Pod 规范下的节点选择器结合使用（这确实是可能的），则节点选择器必须在任何节点亲和性逻辑生效之前满足。这是因为节点选择器只实现硬性要求，并且两者之间没有`OR`逻辑运算符。`OR`逻辑运算符将检查两个要求，并确保它们中至少有一个为真 - 但节点选择器不允许我们这样做。

其次，对于`requiredDuringSchedulingIgnoredDuringExecution`节点亲和性，`nodeSelectorTerms`下的多个条目将在`OR`逻辑运算符中处理。如果满足一个但不是全部，则 Pod 仍将被调度。

最后，对于`matchExpressions`下有多个条目的`nodeSelectorTerm`，所有条目都必须满足 - 这是一个`AND`逻辑运算符。让我们看一个这样的示例 YAML：

pod-with-node-affinity5.yaml

```
apiVersion: v1
kind: Pod
metadata:
  name: affinity-test
spec:
  affinity:
    nodeAffinity:
      requiredDuringSchedulingIgnoredDuringExecution:
        nodeSelectorTerms:
        - matchExpressions:
          - key: cpu_speed
            operator: Gt
            values:
            - "5"
          - key: memory_speed
            operator: Gt
            values:
            - "4"
  containers:
  - name: speedy-app
    image: speedy-app:latest
```

在这种情况下，如果一个节点的 CPU 速度为`5`，但不满足内存速度要求（或反之亦然），则 Pod 将不会被调度。

关于节点亲和性的最后一件事要注意的是，正如您可能已经注意到的，这两种亲和性类型都不允许我们在我们的污点和容忍设置中可以使用的`NoExecute`功能。

另一种节点亲和性类型 - `requiredDuringSchedulingRequiredDuring execution` - 将在将来的版本中添加此功能。截至 Kubernetes 1.19，这种类型尚不存在。

接下来，我们将看一下 Pod 间亲和性和反亲和性，它提供了 Pod 之间的亲和性定义，而不是为节点定义规则。

# 使用 Pod 间亲和性和反亲和性

Pod 间亲和性和反亲和性让您根据节点上已经存在的其他 Pod 来指定 Pod 应该如何运行。由于集群中的 Pod 数量通常比节点数量要大得多，并且一些 Pod 亲和性和反亲和性规则可能相当复杂，如果您在许多节点上运行许多 Pod，这个功能可能会给您的集群控制平面带来相当大的负载。因此，Kubernetes 文档不建议在集群中有大量节点时使用这些功能。

Pod 亲和性和反亲和性的工作方式有很大不同-让我们先单独看看每个，然后再讨论它们如何结合起来。

## Pod 亲和性

与节点亲和性一样，让我们深入讨论 YAML，以讨论 Pod 亲和性规范的组成部分：

pod-with-pod-affinity.yaml

```
apiVersion: v1
kind: Pod
metadata:
  name: not-hungry-app-affinity
spec:
  affinity:
    podAffinity:
      requiredDuringSchedulingIgnoredDuringExecution:
      - labelSelector:
          matchExpressions:
          - key: hunger
            operator: In
            values:
            - "1"
            - "2"
        topologyKey: rack
  containers:
  - name: not-hungry-app
    image: not-hungry-app:latest
```

就像节点亲和性一样，Pod 亲和性让我们在两种类型之间进行选择：

+   `preferredDuringSchedulingIgnoredDuringExecution`

+   `requiredDuringSchedulingIgnoredDuringExecution`

与节点亲和性类似，我们可以有一个或多个选择器-因为我们选择的是 Pod 而不是节点，所以它们被称为`labelSelector`。`matchExpressions`功能与节点亲和性相同，但是 Pod 亲和性添加了一个全新的关键字叫做`topologyKey`。

`topologyKey`本质上是一个选择器，限制了调度器应该查看的范围，以查看是否正在运行相同选择器的其他 Pod。这意味着 Pod 亲和性不仅需要意味着同一节点上相同类型（选择器）的其他 Pod；它可以意味着多个节点的组。

让我们回到本章开头的故障域示例。在那个例子中，每个机架都是自己的故障域，每个机架有多个节点。为了将这个概念扩展到`topologyKey`，我们可以使用`rack=1`或`rack=2`为每个机架上的节点打上标签。然后我们可以使用`topologyKey`机架，就像我们在 YAML 中所做的那样，指定调度器应该检查所有运行在具有相同`topologyKey`的节点上的 Pod（在这种情况下，这意味着同一机架上的`Node 1`和`Node 2`上的所有 Pod）以应用 Pod 亲和性或反亲和性规则。

因此，将我们的示例 YAML 全部加起来，告诉调度器的是：

+   这个 Pod *必须*被调度到具有标签`rack`的节点上，其中标签`rack`的值将节点分成组。

+   然后 Pod 将被调度到一个组中，该组中已经存在一个带有标签`hunger`和值为 1 或 2 的 Pod。

基本上，我们将我们的集群分成拓扑域 - 在这种情况下是机架 - 并指示调度器仅在共享相同拓扑域的节点上将相似的 Pod 一起调度。这与我们第一个故障域示例相反，如果可能的话，我们不希望 Pod 共享相同的域 - 但也有理由希望相似的 Pod 在同一域上。例如，在多租户设置中，租户希望在域上拥有专用硬件租用权，您可以确保属于某个租户的每个 Pod 都被调度到完全相同的拓扑域。

您可以以相同的方式使用`preferredDuringSchedulingIgnoredDuringExecution`。在我们讨论反亲和性之前，这里有一个带有 Pod 亲和性和`preferred`类型的示例：

pod-with-pod-affinity2.yaml

```
apiVersion: v1
kind: Pod
metadata:
  name: not-hungry-app-affinity
spec:
  affinity:
    podAffinity:
      preferredDuringSchedulingIgnoredDuringExecution:
      - weight: 50
        podAffinityTerm:
          labelSelector:
            matchExpressions:
            - key: hunger
              operator: Lt
              values:
              - "3"
          topologyKey: rack
  containers:
  - name: not-hungry-app
    image: not-hungry-app:latest
```

与之前一样，在这个代码块中，我们有我们的`weight` - 在这种情况下是`50` - 和我们的表达式匹配 - 在这种情况下，使用小于（`Lt`）运算符。这种亲和性将促使调度器尽力将 Pod 调度到一个节点上，该节点上已经运行着一个`hunger`小于 3 的 Pod，或者与另一个在同一机架上运行着`hunger`小于 3 的 Pod。调度器使用`weight`来比较节点 - 正如在节点亲和性部分讨论的那样 - *使用节点亲和性控制 Pod*（参见`pod-with-node-affinity4.yaml`）。在这种特定情况下，`50`的权重并没有任何区别，因为亲和性列表中只有一个条目。

Pod 反亲和性使用相同的选择器和拓扑结构来扩展这种范例-让我们详细看一下它们。

## Pod 反亲和性

Pod 反亲和性允许您阻止 Pod 在与匹配选择器的 Pod 相同的拓扑域上运行。它们实现了与 Pod 亲和性相反的逻辑。让我们深入了解一些 YAML，并解释一下它是如何工作的：

pod-with-pod-anti-affinity.yaml

```
apiVersion: v1
kind: Pod
metadata:
  name: hungry-app
spec:
  affinity:
    podAntiAffinity:
      preferredDuringSchedulingIgnoredDuringExecution:
      - weight: 100
        podAffinityTerm:
          labelSelector:
            matchExpressions:
            - key: hunger
              operator: In
              values:
              - "4"
              - "5"
          topologyKey: rack
  containers:
  - name: hungry-app
    image: hungry-app
```

与 Pod 亲和性类似，我们使用`affinity`键来指定`podAntiAffinity`下的反亲和性的位置。与 Pod 亲和性一样，我们可以使用`preferredDuringSchedulingIgnoredDuringExecution`或`requireDuringSchedulingIgnoredDuringExecution`。我们甚至可以使用与 Pod 亲和性相同的选择器语法。

语法上唯一的实际区别是在`affinity`键下使用`podAntiAffinity`。

那么，这个 YAML 文件是做什么的呢？在这种情况下，我们建议调度器（一个`soft`要求）应该尝试将这个 Pod 调度到一个节点上，在这个节点或具有相同值的`rack`标签的任何其他节点上都没有运行带有`hunger`标签值为 4 或 5 的 Pod。我们告诉调度器*尽量不要将这个 Pod 与任何额外饥饿的 Pod 放在一起*。

这个功能为我们提供了一个很好的方法来按故障域分隔 Pod - 我们可以将每个机架指定为一个域，并给它一个与自己相同类型的反亲和性。这将使调度器将 Pod 的克隆（或尝试在首选亲和性中）调度到不在相同故障域的节点上，从而在发生域故障时提供更大的可用性。

我们甚至可以选择结合 Pod 的亲和性和反亲和性。让我们看看这样可以如何工作。

## 结合亲和性和反亲和性

这是一个情况，你可以真正给你的集群控制平面增加不必要的负载。结合 Pod 的亲和性和反亲和性可以允许传递给 Kubernetes 调度器的非常微妙的规则。

让我们看一些结合这两个概念的部署规范的 YAML。请记住，亲和性和反亲和性是应用于 Pod 的概念 - 但我们通常不会指定没有像部署或副本集这样的控制器的 Pod。因此，这些规则是在部署 YAML 中的 Pod 规范级别应用的。出于简洁起见，我们只显示了这个部署的 Pod 规范部分，但你可以在 GitHub 存储库中找到完整的文件。

pod-with-both-antiaffinity-and-affinity.yaml

```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: hungry-app-deployment
# SECTION REMOVED FOR CONCISENESS  
     spec:
      affinity:
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
          - labelSelector:
              matchExpressions:
              - key: app
                operator: In
                values:
                - other-hungry-app
            topologyKey: "rack"
        podAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
          - labelSelector:
              matchExpressions:
              - key: app
                operator: In
                values:
                - hungry-app-cache
            topologyKey: "rack"
      containers:
      - name: hungry-app
        image: hungry-app:latest
```

在这个代码块中，我们告诉调度器将我们的部署中的 Pod 视为这样：Pod 必须被调度到具有`rack`标签的节点上，以便它或具有相同值的`rack`标签的任何其他节点都有一个带有`app=hungry-label-cache`的 Pod。

其次，调度器必须尝试将 Pod 调度到具有`rack`标签的节点上，以便它或具有相同值的`rack`标签的任何其他节点都没有运行带有`app=other-hungry-app`标签的 Pod。

简而言之，我们希望我们的`hungry-app`的 Pod 在与`hungry-app-cache`相同的拓扑结构中运行，并且如果可能的话，我们不希望它们与`other-hungry-app`在相同的拓扑结构中。

由于强大的力量伴随着巨大的责任，而我们的 Pod 亲和性和反亲和性工具既强大又降低性能，Kubernetes 确保对您可以使用它们的可能方式设置了一些限制，以防止奇怪的行为或重大性能问题。

## Pod 亲和性和反亲和性限制

亲和性和反亲和性的最大限制是，您不允许使用空的`topologyKey`。如果不限制调度器将作为单个拓扑类型处理的内容，可能会发生一些非常意外的行为。

第二个限制是，默认情况下，如果您使用反亲和性的硬版本-`requiredOnSchedulingIgnoredDuringExecution`，您不能只使用任何标签作为`topologyKey`。

Kubernetes 只允许您使用`kubernetes.io/hostname`标签，这基本上意味着如果您使用`required`反亲和性，您只能在每个节点上有一个拓扑。这个限制对于`prefer`反亲和性或任何亲和性都不存在，甚至是`required`。可以更改此功能，但需要编写自定义准入控制器-我们将在*第十二章*中讨论，*Kubernetes 安全性和合规性*，以及*第十三章*，*使用 CRD 扩展 Kubernetes*。

到目前为止，我们对放置控件的工作尚未讨论命名空间。但是，对于 Pod 亲和性和反亲和性，它们确实具有相关性。

## Pod 亲和性和反亲和性命名空间

由于 Pod 亲和性和反亲和性会根据其他 Pod 的位置而改变行为，命名空间是决定哪些 Pod 计入或反对亲和性或反亲和性的相关因素。

默认情况下，调度器只会查看创建具有亲和性或反亲和性的 Pod 的命名空间。对于我们之前的所有示例，我们没有指定命名空间，因此将使用默认命名空间。

如果要添加一个或多个命名空间，其中 Pod 将影响亲和性或反亲和性，可以使用以下 YAML：

pod-with-anti-affinity-namespace.yaml

```
apiVersion: v1
kind: Pod
metadata:
  name: hungry-app
spec:
  affinity:
    podAntiAffinity:
      preferredDuringSchedulingIgnoredDuringExecution:
      - weight: 100
        podAffinityTerm:
          labelSelector:
            matchExpressions:
            - key: hunger
              operator: In
              values:
              - "4"
              - "5"
          topologyKey: rack
          namespaces: ["frontend", "backend", "logging"]
  containers:
  - name: hungry-app
    image: hungry-app
```

在这个代码块中，调度器将在尝试匹配反亲和性时查看前端、后端和日志命名空间（如您在`podAffinityTerm`块中的`namespaces`键中所见）。这允许我们限制调度器在验证其规则时操作的命名空间。

# 总结

在本章中，我们了解了 Kubernetes 提供的一些不同控件，以强制执行调度器通过规则来放置 Pod。我们了解到有“硬”要求和“软”规则，后者是调度器尽最大努力但不一定阻止违反规则的 Pod 被放置。我们还了解了一些实施调度控件的原因，比如现实生活中的故障域和多租户。

我们了解到有一些简单的方法可以影响 Pod 的放置，比如节点选择器和节点名称，还有更高级的方法，比如污点和容忍，Kubernetes 本身也默认使用这些方法。最后，我们发现 Kubernetes 提供了一些高级工具，用于节点和 Pod 的亲和性和反亲和性，这些工具允许我们创建复杂的调度规则。

在下一章中，我们将讨论 Kubernetes 上的可观察性。我们将学习如何查看应用程序日志，还将使用一些很棒的工具实时查看我们集群中正在发生的事情。

# 问题

1.  节点选择器和节点名称字段之间有什么区别？

1.  Kubernetes 如何使用系统提供的污点和容忍？出于什么原因？

1.  在使用多种类型的 Pod 亲和性或反亲和性时，为什么要小心？

1.  如何在多个故障区域之间平衡可用性，并出于性能原因进行合作，为三层 Web 应用程序提供一个例子？使用节点或 Pod 的亲和性和反亲和性。

# 进一步阅读

+   要了解有关默认系统污点和容忍的更深入解释，请访问[`kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/#taint-based-evictions`](https://kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/#taint-based-evictions)。
