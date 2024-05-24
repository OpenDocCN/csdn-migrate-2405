# 面向 Java 开发者的 Docker 和 Kubernetes 教程（三）

> 原文：[`zh.annas-archive.org/md5/232C7A0FCE93C7B650611F281F88F33B`](https://zh.annas-archive.org/md5/232C7A0FCE93C7B650611F281F88F33B)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：使用 Java 与 Kubernetes

在第七章中，*Kubernetes 简介*，我们了解了 Kubernetes 的架构和概念。我们知道节点、Pod 和服务。在本章中，我们将进行一些实际的实践，并将我们的 Java REST 服务部署到本地 Kubernetes 集群。为了学习目的，我们将使用 Minikube 工具在本地机器上创建一个集群。在第一次学习时，最好在本地机器上学习 Kubernetes，而不是直接去云端。因为 Minikube 在本地运行，而不是通过云提供商，某些特定于提供商的功能，如负载均衡器和持久卷，将无法直接使用。但是，您可以使用`NodePort`、`HostPath`、持久卷和一些插件，如 DNS 或仪表板，在将应用程序推送到真正的、生产级别的集群之前，在本地测试您的应用程序。在第十章中，*在云中部署 Java 到 Kubernetes*，我们将在**Amazon Web Services**（**AWS**）和 Google 容器引擎中运行 Kubernetes。

为了跟上，我们需要准备好以下工具：

+   `Docker`：构建我们想要部署的 Docker 镜像

+   `minikube`：本地 Kubernetes 环境

+   `kubectl`：Kubernetes 命令行界面

本章将涵盖以下主题：

+   在 macOS、Windows 和 Linux 上安装 Minikube

+   使用 Minikube 启动本地 Kubernetes 集群

+   在本地集群上部署 Java 应用程序

+   与容器交互：扩展、自动扩展和查看集群事件

+   使用 Kubernetes 仪表板

我假设你到目前为止已经安装并运行了 Docker，所以让我们专注于`minikube`实用程序。我们已经在第七章中提到了`minikube`，*Kubernetes 简介*；现在，我们将详细介绍一些内容，从安装过程开始。

# 安装 Minikube

Minikube 工具源代码和所有文档都可以在 GitHub 上找到[`github.com/kubernetes/minikube`](https://github.com/kubernetes/minikube)。

# 在 Mac 上安装

以下命令序列将下载`minikube`二进制文件，设置可执行标志并将其复制到`/usr/local/bin`文件夹，这将使其在 macOS shell 中可用：

```
$ curl -Lo minikube https://storage.googleapis.com/minikube/releases/v0.12.2/minikube-darwin-amd64

$ chmod +x minikube

$ sudo mv minikube /usr/local/bin/

```

或者，如果您使用 Homebrew 软件包管理器（可以在[`brew.sh`](https://brew.sh)免费获得），这是非常方便和推荐的，您可以通过输入以下命令来安装`minikube`：

```
$ brew cask install minikube

```

# 在 Windows 上安装

Windows 上的 Minikube 也只是一个可执行文件。您可以在 Minikube 的网站[`github.com/kubernetes/minikube`](https://github.com/kubernetes/minikube)上找到最新版本。您只需要下载最新的可执行文件，将其重命名为`minikube.exe`，并将其放在系统路径中，以便从命令行中使用。

# 在 Linux 上安装

在 Linux 上的安装过程与 macOS 相同。唯一的区别是可执行文件的名称。以下命令将下载最新的 Minikube 版本，设置可执行位，并将其移动到`/usr/local/bin`目录中：

```
$ curl -Lo minikube https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64 && chmod +x minikube && sudo mv minikube /usr/local/bin/

```

就是这样，一个 Minikube 和 Docker 就足以启动本地集群。是时候让它活起来了：

# 启动本地 Kubernetes 集群

我们正在使用`minikube`提供的本地 Kubernetes 集群。使用以下命令启动您的集群：

```
$ minikube start

```

Minikube 在自己的虚拟机上运行。根据您的主机操作系统，您可以在几个虚拟化驱动程序之间进行选择。目前支持的有`virtualbox`，`vmwarefusion`，`xhyve`，`hyperv`和`kvm`（基于内核的虚拟机）。默认的 VM 驱动程序是 virtual box。您可以覆盖此选项。这是使用`xhyve`的 macOS 启动命令行的示例：

```
$ minikube start --vm-driver=xhyve

```

首次启动 Minikube 时，您会看到它正在下载 Minikube ISO，因此该过程将需要更长一点时间。不过，这是一次性操作。Minikube 配置将保存在您的`home`目录中的`.minikube`文件夹中，例如在 Linux 或 macOS 上为`~/.minikube`。在第一次运行时，Minikube 还将配置`kubectl`命令行工具（我们将在短时间内回到它）以使用本地的`minikube`集群。此设置称为`kubectl`上下文。它确定`kubectl`正在与哪个集群交互。所有可用的上下文都存在于`~/.kube/config`文件中。

由于集群现在正在运行，并且我们默认启用了`dashboard`插件，您可以使用以下命令查看（仍然为空的）Kubernetes 仪表板：

```
$ minikube dashboard

```

它将用集群仪表板的 URL 打开您的默认浏览器：

**![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00084.jpg)**

如您所见，仪表板现在是空的。如果您浏览到命名空间菜单，您会注意到 Minikube 创建了一些命名空间，其中一个可用于我们的目的，简单地命名为默认。Minikube 安装的部分，例如 DNS 或仪表板，也在集群本身上运行，具有单独的命名空间，如 kube-public 和 kube-system。

随意浏览菜单和部分；目前还没有造成任何伤害，这是一个本地开发集群，什么都没有运行。我们将在本章的最后一节回到仪表板，看看我们如何可以使用它来从漂亮的 UI 部署我们的服务，如果你更喜欢这样做，而不是使用命令行的 shell。

当然，让集群空转是相当无用的，所以我们需要一个工具来管理它。虽然我们几乎可以使用仪表板来完成所有事情，但使用命令行工具会更方便。`kubectl`控制 Kubernetes 集群。我们将大量使用`kubectl`命令行工具来部署、调度和扩展我们的应用程序和微服务。该工具作为 Mac、Linux 和 Windows 的独立二进制文件提供。在下一节中，您将找到不同平台的安装说明。

# 安装 kubectl

`kubectl`适用于所有主要平台。让我们从 macOS 安装开始。

# 在 Mac 上安装

以下命令序列将下载`kubectl`二进制文件，设置可执行标志并将其复制到`/usr/local/bin`文件夹中，这将使其在 macOS shell 中可用：

```
$ curl -O https://storage.googleapis.com/kubernetes-release/release/v1.5.2

/bin/darwin/amd64/kubectl

$ chmod +x kubectl

$ sudo cp kubectl /usr/local/bin

```

Homebrew 提供了安装`kubectl`并保持其最新的最便捷方式。要安装，请使用此命令：

```
$ brew install kubectl

```

要更新，请使用以下命令：

```
$ brew upgrade kubectl

```

# 在 Windows 上安装

您可以在 GitHub 上找到 Windows `kubectl`的发布列表[`github.com/eirslett/kubectl-windows/releases`](https://github.com/eirslett/kubectl-windows/releases) 。与 Minikube 类似，kubectl 只是一个单独的`.exe`文件。在撰写本书时，它是[`github.com/eirslett/kubectl-windows/releases/download/v1.6.3/kubectl.exe`](https://github.com/eirslett/kubectl-windows/releases/download/v1.6.3/kubectl.exe) 。您需要下载`exe`文件并将其放在系统路径上，以便在命令行中使用。

# 在 Linux 上安装

安装过程与 macOS 非常相似。以下命令将获取`kubectl`二进制文件，给予可执行标志，然后将其移动到`/usr/local/bin`中，以便在 shell 中使用：

```
$ curl -O https://storage.googleapis.com/kubernetes-release/release/v1.5.2

/bin/linux/amd64/kubectl

$ chmod +x kubectl

$ sudo cp kubectl /usr/local/bin/kubectl

```

要验证您的本地集群是否已启动并且`kubectl`已正确配置，请执行以下命令：

```
$ kubectl cluster-info 

```

在输出中，您将获得有关集群的基本信息，包括其 IP 地址和运行的 Minikube 插件（我们将在本章后面再回到插件）：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00085.jpg)

要列出我们集群中正在运行的节点，执行`get nodes`命令：

```
$ kubectl get nodes

```

当然，这只是一个单节点集群，所以在上一个命令的输出中没有什么意外：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00086.jpg)

我们的集群已经启动运行了；现在是时候在上面部署我们的服务了。

# 在 Kubernetes 集群上部署

我们通过定义一个服务来开始在 Kubernetes 集群上部署我们的软件。正如您从第七章 *Kubernetes 简介*中记得的那样，服务将一组 Pods 抽象为单个 IP 和端口，允许简单的 TCP/UDP 负载，并允许 Pods 列表动态更改。让我们从创建服务开始。

# 创建服务

默认情况下，每个 Pod 只能在 Kubernetes 集群内部通过其内部 IP 地址访问。为了使容器可以从 Kubernetes 虚拟网络外部访问，我们需要将 Pod 公开为 Kubernetes 服务。要创建一个服务，我们将使用简单的`.yaml`文件，其中包含服务清单。YAML 是一种人类可读的数据序列化语言，通常用于配置文件。我们的 Java `rest-example`的示例服务清单可能看起来与以下内容相同：

```
apiVersion: v1

kind: Service

metadata:

 name: rest-example

 labels:

 app: rest-example

 tier: backend

spec:

 type: NodePort

 ports:

 - port: 8080

 selector:

 app: rest-example

 tier: backend

```

请注意，服务的清单不涉及 Docker 镜像。这是因为，正如您从第七章 *Kubernetes 简介*中记得的那样，Kubernetes 中的服务只是一个提供网络连接给一个或多个 Pod 的抽象。每个服务都有自己的 IP 地址和端口，其在服务的生命周期内保持不变。每个 Pod 都需要具有特定的标签，以便服务发现，服务使用和标签`selectors`来分组查找 Pods。在我们之前的示例中，`selector`将挑选出所有具有标签`app`值为`rest-example`和标签名为`tier`值为`backend`的 Pods：

```
selector:

 app: rest-example

 tier: backend

```

正如您在第七章中所记得的，*Kubernetes 简介*，Kubernetes 集群中的每个节点都运行一个 kube-proxy 进程。kube-proxy 在 Kubernetes 服务中扮演着至关重要的角色。它的目的是为它们公开虚拟 IP。自 Kubernetes 1.2 以来，iptables 代理是默认设置。您可以使用两种选项来设置代理：用户空间和 iptables。这些设置指的是实际处理连接转发的内容。在两种情况下，都会安装本地 iptables 规则来拦截具有与服务关联的目标 IP 地址的出站 TCP 连接。这两种模式之间有一个重要的区别：

+   代理模式：用户空间：在用户空间模式下，iptables 规则转发到一个本地端口，kube-proxy 正在监听连接。运行在用户空间的 kube-proxy 终止连接，与服务的后端建立新连接，然后将请求转发到后端，并将响应返回给本地进程。用户空间模式的优势在于，因为连接是从应用程序创建的，如果连接被拒绝，应用程序可以重试到不同的后端。

+   代理模式：iptables：在这种模式下，iptables 规则被安装直接将目的地为服务的数据包转发到服务的后端。这比将数据包从内核移动到 kube-proxy 然后再返回内核更有效，因此会产生更高的吞吐量和更好的尾延迟。然而，与用户空间模式不同，使用 iptables 模式会使得如果最初选择的 Pod 不响应，则无法自动重试另一个 Pod，因此它依赖于工作的就绪探针。

正如您所看到的，在这两种情况下，节点上都会运行 kube-proxy 二进制文件。在用户空间模式下，它会将自己插入为代理；在 iptables 模式下，它将配置 iptables 而不是自己代理连接。

服务类型可以具有以下值：

+   NodePort：通过指定`NodePort`服务类型，我们声明将服务暴露到集群外部。Kubernetes 主节点将从配置的标志范围（默认值：30000-32767）分配一个端口，集群的每个节点将代理该端口（每个节点上的相同端口号）到您的服务。

+   **负载均衡器**：这将在支持外部负载均衡器的云提供商（例如在 Amazon AWS 云上）上创建负载均衡器。在使用 Minikube 时，此功能不可用。

+   **Cluster IP**：这将仅在集群内部公开服务。这是默认值，如果您不提供其他值，将使用此值。

准备好我们的`service.yml`文件后，我们可以通过执行以下`kubectl`命令来创建我们的第一个 Kubernetes 服务：

```
$ kubectl create -f service.yml

```

要查看我们的服务是否正确创建，我们可以执行`kubectl get services`命令：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00087.jpg)

我们还可以通过添加`--all-namespaces`开关来列出其他服务（包括`minikube`集群本身提供的服务，如果您感兴趣）。

```
$ kubectl get services --all-namespaces

```

查看特定服务的详细信息，我们使用`describe`命令。执行以下命令以查看我们的`rest-example` Java 服务的详细信息：

```
$ kubectl describe service rest-example

```

在输出中，我们呈现了最有用的服务属性，特别是端点（我们的内部容器 IP 和端口，在这种情况下只有一个，因为我们有一个 Pod 在服务中运行），服务内部端口和代理的 NodePort：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00088.jpg)

将所有设置放在`.yaml`文件中非常方便。但有时，需要以更动态的方式创建服务；例如在一些自动化流程中。在这种情况下，我们可以通过向`kubectl`命令本身提供所有参数和选项，手动创建服务，而不是首先创建`.yaml`文件。但在执行此操作之前，您需要先创建部署，因为手动创建服务只是使用`kubectl`命令公开部署。毕竟，服务是一个公开的部署，实际上只是一组 Pod。这样公开的示例，将导致服务创建，看起来与这个相同：

```
$ kubectl expose deployment rest-example--type="NodePort"

```

# 创建部署

在创建部署之前，我们需要准备好并发布到注册表的 Docker 镜像，例如 Docker Hub。当然，它也可以是您组织中托管的私有存储库。正如您从第七章中记得的，*Kubernetes 简介*，Pod 中的每个 Docker 容器都有自己的镜像。默认情况下，Pod 中的 kubectl 进程将尝试从指定的注册表中拉取每个镜像。您可以通过在部署描述符中为`imagePullPolicy`属性指定值来更改此行为。它可以具有以下值：

+   `IfNotPresent`：使用此设置，仅当本地主机上不存在图像时，才会从注册表中提取图像

+   `Never`：使用此选项，kubelet 将仅使用本地图像。

在创建部署时，使用值`IfNotPresent`设置`imagePullPolicy`很有用；否则，Minikube 将在查找本地主机上的图像之前尝试下载图像。

Kubernetes 使用与 Docker 本身相同的图像语法，包括私有注册表和标记。

重要的是您在图像名称中提供标记。否则，Kubernetes 将在存储库中查找图像时使用最新标记，与 Docker 一样。

在本地构建图像时，与本地 Kubernetes 集群一起工作会有点棘手。Minikube 在单独的 VM 中运行，因此它不会看到您在本地使用 Docker 在计算机上构建的图像。有一个解决方法。您可以执行以下命令：

```
$ eval $(minikube docker-env)

```

先前的命令实际上将利用在`minikube`上运行的 Docker 守护程序，并在 Minikube 的 Docker 上构建您的图像。这样，本地构建的图像将可供 Minikube 使用，而无需从外部注册表中提取。这并不是很方便，将 Docker 图像推送到`远程`注册表肯定更容易。让我们将我们的 rest-example 图像推送到`DockerHub`注册表。

1.  首先，我们需要登录：

```
$ docker login

```

1.  然后，我们将使用`docker tag`命令标记我们的图像（请注意，您需要提供自己的 DockerHub 用户名，而不是`$DOCKER_HUB_USER`）：

```
$ docker tag 54529c0ebed7 $DOCKER_HUB_USER/rest-example

```

1.  最后一步将是使用`docker push`命令将我们的图像推送到 Docker Hub：

```
$ docker push $DOCKER_HUB_USER/rest-example

```

1.  现在我们在注册表中有一个可用的图像，我们需要一个部署清单。这又是一个`.yaml`文件，看起来可能与此相同：

```
 apiVersion: extensions/v1beta1

kind: Deployment

metadata:

  name: rest-example

spec:

  replicas: 1

  template:

    metadata:

      labels:

        app: rest-example

        tier: backend

    spec:

      containers:

      - name: rest-example

        image: jotka/rest-example

        imagePullPolicy: IfNotPresent

        resources:

          requests:

            cpu: 100m

            memory: 100Mi

        env:

        - name: GET_HOSTS_FROM

          value: dns

        ports:

        - containerPort: 8080

```

在集群上使用`kubectl`创建此部署，您需要执行以下命令，与创建服务时完全相同，只是文件名不同：

```
$ kubectl create -f deployment.yml

```

！[](Image00089.jpg)

您可以查看部署属性：

```
$ kubectl describe deployment rest-service

```

！[](Image00090.jpg)

如您所见，已创建一个 Pod 以及一个 ReplicaSet 和默认的滚动更新策略。您还可以查看 Pods：

```
$ kubectl get pods

```

`get pods`命令的输出将给出部署中运行的 Pod 的名称。稍后这将很重要，因为如果要与特定的 Pod 交互，您需要知道其名称：

！[](Image00091.jpg)

作为`.yaml`文件中部署描述符的替代方案，您可以使用`kubectl run`命令和选项从命令行创建部署，如下例所示：

```
$ kubectl run rest-example --image=jotka/rest-example --replicas=1 --port=8080 --labels="app:rest-example;tier:backend" --expose 

```

让我们总结一下与创建资源和获取有关它们的信息相关的`kubectl`命令，以及一些示例，放在表中：

| **示例命令** | **意义** |
| --- | --- |
| `kubectl create -f ./service.yaml` | 创建资源 |
| `kubectl create -f ./service.yaml -f ./deployment.yaml` | 从多个文件创建 |
| `kubectl create -f ./dir` | 在指定目录中的所有清单文件中创建资源 |
| `kubectl create -f https://sampleUrl` | 从 URL 创建资源 |
| `kubectl run nginx --image=nginx` | 启动 nginx 的单个实例 |
| `Kubectl get pods` | 获取`pod`的文档 |
| `kubectl get pods --selector=app=rest-example` | 列出与指定标签`selector`匹配的所有 Pod |
| `kubectl explain pods` | 显示所有 Pod 的详细信息 |
| `kubectl get services` | 列出所有已创建的服务 |
| `kubectl explain service` | 显示指定服务的详细信息 |
| `kubectl explain services` | 显示所有已创建服务的详细信息 |
| `kubectl get deployments` | 列出所有已创建的部署 |
| `kubectl get deployment` | 显示指定服务的详细信息 |
| `kubectl explain deployment` | 显示指定部署的详细信息 |
| `kubectl explain deployments` | 显示所有已创建部署的详细信息 |
| `kubectl get nodes` | 列出所有集群节点 |
| `kubectl explain node` | 显示指定节点的详细信息 |

```
 Calling the service

```

正如我们在`kubectl describe service rest-example`命令输出中所看到的，我们的`rest-example service`可以通过端口`8080`和域名`rest-example`在集群内部访问。在我们的情况下，端点的完整 URL 将是`http://rest-example:8080`。然而，为了能够从外部世界执行服务，我们使用了`NodePort`映射，并且我们知道它被赋予了端口`31141`。我们所需要的只是集群的 IP 来调用服务。我们可以使用以下命令获取它：

```
$ minikube ip

```

有一个快捷方式可以了解外部可访问的服务 URL 和端口号。我们可以使用`minikube service`命令来告诉我们确切的服务地址：

```
$ minikube service rest-example --url

```

上一个命令的输出将是带有映射端口号的服务 URL。如果您跳过`--url`开关，`minikube`将只是使用您的默认 Web 浏览器打开服务的 URL。这有时很方便。

拥有端点的完整 URL 后，我们可以使用任何`HTTP`客户端（例如`curl`）访问服务：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00092.jpg)

当服务运行时，应用程序日志通常可以帮助您了解集群内部发生了什么。日志对于调试问题和监视集群活动特别有用。让我们看看如何访问我们的容器日志。

# 与容器交互和查看日志

大多数现代应用程序都有某种日志记录机制。例如，我们的 Java REST 服务使用 slf4j 从 REST 控制器输出日志。容器化应用程序最简单和最简单的日志记录方法就是写入标准输出和标准错误流。Kubernetes 支持这一点。

假设我们已经使用浏览器或 curl 向我们的新 Web 服务发送了请求，现在应该能够看到一些日志。在此之前，我们需要有一个 Pod 的名称，在部署过程中会自动创建。要获取 Pod 的名称，请使用`kubectl get pods`命令。之后，您可以显示指定 Pod 的日志：

```
$ kubectl logs rest-example-3660361385-gkzb8

```

如您在以下截图中所见，我们将访问来自 Pod 中运行的服务的著名 Spring Boot 横幅：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00093.jpg)

查看日志并不是我们可以对特定 Pod 进行的唯一操作。与 Docker 类似（实际上，Pod 正在运行 Docker），我们可以使用`kubectl exec`命令与容器进行交互。例如，要获取正在运行的容器的 shell：

```
$ kubectl exec -it rest-example-3660361385-gkzb8 -- /bin/bash

```

上一个命令将把您的 shell 控制台附加到正在运行的容器中的 shell，您可以与之交互，例如列出进程，就像您在以下截图中所见的那样：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00094.jpg)

`kubectl exec`命令的语法与 Docker 中的`exec`命令非常相似，只有一个小差别，正如您从第七章中所记得的，*Kubernetes 简介*，一个 Pod 可以运行多个容器。在这种情况下，我们可以使用`--container`或`-c`命令开关来指定`kubectl exec`命令中的容器。例如，假设我们有一个名为`rest-example-3660361385-gkzb8`的 Pod。这个 Pod 有两个名为 service 和 database 的容器。以下命令将打开一个 shell 到 service 容器：

```
$ kubectl exec -it rest-example-3660361385-gkzb8 --container service -- /bin/bash

```

拥有查看日志和与容器交互的可能性为您提供了很大的灵活性，可以准确定位您在运行 Pod 时可能遇到的问题。让我们总结与查看日志和与 Pod 交互相关的 `kubectl` 命令表：

| **示例命令** | **意义** |
| --- | --- |
| `kubectl logs myPod` | 转储 pod 日志（stdout） |
| `kubectl logs myPod -c myContainer` | 转储 pod 容器日志（stdout，多容器情况） |
| `kubectl logs -f myPod` | 流式传输 pod 日志（stdout） |
| `kubectl logs -f myPod -c myContainer` | 流式传输 pod 容器日志（stdout，多容器情况） |
| `kubectl run -i --tty busybox --image=busybox -- sh` | 以交互式 shell 运行 pod |
| `kubectl attach myPod -i` | 连接到正在运行的容器 |
| `kubectl port-forward myPod 8080:8090` | 将 Pod 的端口 `8080` 转发到本地机器上的 `8090` |
| `kubectl exec myPod -- ls /` | 在现有 pod 中运行命令（单容器情况） |
| `kubectl exec myPod -c myContainer -- ls /` | 在现有 pod 中运行命令（多容器情况） |
| `kubectl top pod POD_NAME --containers` | 显示给定 pod 及其容器的指标 |

正如您已经知道的那样，Pod 和容器是脆弱的。它们可能会崩溃或被杀死。您可以使用 `kubectl` logs 命令检索具有 `--previous` 标志的容器的先前实例化的日志，以防容器崩溃。假设我们的服务运行良好，但由于第七章 *Kubernetes 简介* 中描述的原因，例如更高的负载，您决定增加运行的容器数量。Kubernetes 允许您增加每个服务运行的 Pod 实例的数量。这可以手动或自动完成。让我们首先关注手动扩展。

# 手动扩展

部署创建后，新的 ReplicaSet 也会自动创建。正如您在第七章 *Kubernetes 简介*中所记得的那样，ReplicaSet 确保在任何给定时间运行指定数量的 Pod 克隆，称为`副本`。如果太多，其中一些将被关闭。如果需要更多，例如如果其中一些因错误或崩溃而死亡，将创建新的 Pod。请注意，如果尝试直接扩展 ReplicaSet，那么它将（在很短的时间内）具有所需的 Pod 数量，例如三个。但是，如果部署控制器看到您已将副本集修改为三个，因为它知道应该是一个（在部署清单中定义），它将将其重置为一个。通过手动修改为您创建的副本集，您有点违背了系统控制器。

需要扩展部署而不是直接扩展副本集。

当然，我们的 Java `rest-example`服务将数据保存在内存中，因此它不是无状态的，因此它可能不是扩展的最佳示例；如果另一个实例被启动，它将拥有自己的数据。但是，它是一个 Kubernetes 服务，因此我们可以使用它来演示扩展。要将我们的`rest-example`部署从一个扩展到三个 Pod，请执行以下`kubectl scale`命令：

```
$ kubectl scale deployment rest-example --replicas=3

```

过一段时间，为了检查，执行以下命令，您将看到部署中现在运行着三个 Pod：

```
$ kubectl get deployments

$ kubectl get pods

```

在下表中，您可以看到与手动扩展相关的一些`kubectl`命令的更多示例：

| **示例命令** | **意义** |
| --- | --- |
| `kubectl scale deployment rest-example --replicas=3` | 将名为`rest-example`的部署扩展到`3`个 Pod |
| `kubectl scale --replicas=3 -f deployment.yaml` | 将`deployment.yaml`文件中指定的资源扩展到`3` |
| `kubectl scale deployment rest-example --current-replicas=2 --replicas=3` | 如果名为`rest-example`的部署当前大小为`2`，则将其扩展到`3`个 Pod |
| `kubectl scale --replicas=5 deployment/foo deployment/bar` | 一次扩展多个部署 |

如果服务负载增加，Kubernetes 可以自动进行扩展。

# 自动缩放

通过水平 Pod 自动缩放，Kubernetes 根据观察到的 CPU 利用率自动调整部署或 ReplicaSet 中 Pod 的数量。Kubernetes 控制器定期调整部署中 Pod“副本”的数量，以匹配观察到的平均 CPU 利用率与您指定的目标。

水平自动缩放器只是 Kubernetes 中的另一种资源类型，因此我们可以像创建其他资源一样使用`kubectl`命令创建它：

+   `kubectl get hpa`：列出自动缩放器

+   `kubectl describe hpa`：获取详细描述

+   `kubectl delete hpa`：删除自动缩放器

此外，还有一个特殊的`kubectl autoscale`命令，用于轻松创建水平 Pod 自动缩放器。一个示例可能是：

```
$ kubectl autoscale deployment rest-example --cpu-percent=50 --min=1 --max=10

```

上一个命令将为我们的`rest-example`部署创建一个自动缩放器，目标 CPU 利用率设置为`50%`，`副本`数量在`1`和`10`之间。

所有集群事件都被注册，包括手动或自动缩放产生的事件。查看集群事件在监视我们的集群上执行的确切操作时可能会有所帮助。

# 查看集群事件

查看集群事件，请输入以下命令：

```
$ kubectl get events

```

它将呈现一个巨大的表格，其中包含集群上注册的所有事件：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00095.jpg)

表格将包括节点状态的更改，拉取 Docker 镜像，启动和停止容器等事件。查看整个集群的情况非常方便。

# 使用 Kubernetes 仪表板

Kubernetes 仪表板是 Kubernetes 集群的通用、基于 Web 的 UI。它允许用户管理运行在集群中的应用程序并对其进行故障排除，以及管理集群本身。我们还可以编辑部署、服务或 Pod 的清单文件。更改将立即被 Kubernetes 接管，因此它使我们能够扩展或缩减部署，例如。

如果您使用`minikube dashboard`命令打开仪表板，它将在默认浏览器中打开一个仪表板 URL。从这里，您可以列出集群上的所有资源，例如部署、服务、Pod 等。正如您在下面的屏幕截图中所看到的，我们的仪表板不再是空的；我们有一个名为`rest-example`的部署：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00096.jpg)

如果您点击它的名称，您将进入部署详细信息页面，它将显示您可以使用`kubectl describe deployment`命令获取的相同信息，但具有良好的 UI：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00097.jpg)

仪表板不仅是只读实用程序。每个资源都有一个方便的菜单，您可以使用它来删除或编辑其清单：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00098.jpg)

如果您选择查看/编辑 YAML 菜单选项，您将能够使用方便的编辑器编辑清单：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00099.jpg)

请注意，如果您更改一个值，例如`replicas`的数量，并单击“更新”，更改将被发送到 Kubernetes 并执行。这样，您也可以例如扩展您的部署。

由于部署已自动创建了一个 ReplicaSet，因此 ReplicaSet 也将显示在仪表板上：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00100.jpg)

服务也是一样的。如果您浏览到服务菜单，它将显示在集群上创建的所有服务的列表：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00101.jpg)

单击服务名称将带您转到详细信息页面：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00102.jpg)

在详细信息屏幕上，列出了所有重要信息。这包括标签选择器，用于查找 Pod 的端口类型，集群 IP，内部端点，当然还有运行在服务内部的 Pod 的列表。通过单击 Pod 的名称，您可以查看正在运行的 Pod 的详细信息，包括其日志输出，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00103.jpg)

仪表板是一个非常方便的工具，可以与现有的部署、服务和 Pod 进行交互。但还有更多。如果您单击仪表板工具栏右上角的“创建”按钮，将显示一个“部署容器化应用程序”屏幕。从这里，您实际上可以创建一个新的部署：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00104.jpg)

您有机会使用`.yaml`文件，就像我们之前使用命令行一样，但是您还可以手动指定部署的详细信息，提供应用程序名称，并且可以选择创建一个服务用于部署。相当方便，不是吗？仪表板只是 Minikube 可用的插件之一。让我们看看我们还有什么可以使用。

# Minikube 插件

Minikube 带有几个插件，例如 Kubernetes 仪表板，Kubernetes DNS 等。我们可以通过执行以下命令列出可用的插件：

```
$ minikube addons list

```

上一个命令的输出将列出可用的插件及其当前状态，例如：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00105.jpg)

要启用或禁用插件，我们使用`minikube addons disable`或`minikube addons enable`，例如：

```
$ minikube addons disable dashboard

$ minikube addons enable heapster

```

如果插件已启用，我们可以通过执行`addon open`命令打开相应的 Web 用户界面，例如：

```
$ minikube addons open heapster

```

# 清理

如果您完成了部署和服务的操作，或者想要从头开始，您可以通过删除部署或服务来清理集群：

```
$ kubectl delete deployment rest-example

$ kubectl delete service rest-example

```

这段代码也可以合并成一个命令，例如：

```
$ kubectl delete service,deployment rest-example

```

`kubectl delete`支持标签`selectors`和命名空间。让我们在表中看一些命令的其他示例：

| **示例命令** | **含义** |
| --- | --- |
| `kubectl delete pod,service baz foo` | 删除具有相同名称`baz`和`foo`的 pod 和服务 |
| `kubectl delete pods,services -l name=myLabel` | 删除具有标签`name=myLabel`的 pod 和服务 |
| `kubectl -n my-ns delete po,svc --all` | 删除命名空间`my-ns`中的所有 pod 和服务 |

要停止`minikube`集群，只需发出：

```
$ minikube stop

```

如果您想要删除当前的`minikube`集群，可以发出以下命令来执行：

```
$ minikube delete

```

# 总结

正如您所看到的，Minikube 是尝试 Kubernetes 并在本地开发中使用它的简单方法。运行本地集群并不像开始时看起来那么可怕。最重要的是，本地的`minikube`集群是一个有效的 Kubernetes 集群。如果您通过在本地玩耍来了解 Kubernetes，您将能够在真实的云中部署您的应用程序而不会遇到任何问题。让我们总结一下我们需要执行的步骤，以使我们的 Java 应用程序在 Kubernetes 集群上运行。

首先，我们需要为我们的微服务编写一些代码。这可以基于您想要的任何内容，可以是在 Tomcat、JBoss 或 Spring Bootstrap 上运行的微服务。没关系，您只需选择您希望软件运行的技术：

+   接下来，将代码放入 Docker 镜像中。您可以通过手动创建 Dockerfile 来完成，也可以使用 Docker Maven 插件来自动化此过程

+   创建 Kubernetes 元数据，如部署清单和服务清单

+   通过部署和创建服务来应用元数据

+   根据您的需求扩展您的应用程序

+   从命令行或仪表板管理您的集群

在第九章中，*使用 Kubernetes API*，我们将深入了解 Kubernetes API。这是与 Kubernetes 集群进行交互的绝佳方式。由于 API 的存在，可能性几乎是无限的，您可以创建自己的开发流程，例如使用 Jenkins 进行持续交付。拥有 API，您不仅仅局限于现有工具来部署软件到 Kubernetes。事情可能会变得更有趣。


# 第九章：使用 Kubernetes API。

在第七章中，*Kubernetes 简介*，和第八章，*使用 Java 与 Kubernetes*，我们学习了 Kubernetes 的概念，并通过安装本地 Kubernetes 集群`minikube`来实践使用它们。我们了解了 Kubernetes 架构的所有组件，比如 pod、节点、部署和服务等。我们还提到了驻留在 Master 节点上的主要组件之一，即 API 服务器。正如你在第七章中所记得的，API 服务器在技术上是一个名为`kube-apiserver`的进程，它接受并响应使用 JSON 的`HTTP REST`请求。API 服务器的主要目的是验证和处理集群资源的数据，比如 Pod、服务或部署等。API 服务器是中央管理实体。它也是唯一直接连接到`etcd`的 Kubernetes 组件，`etcd`是 Kubernetes 存储其所有集群状态的分布式键值数据存储。

在之前的章节中，我们一直在使用`kubectl`命令行工具来管理我们的集群。`kubectl`是一个有用的实用工具，每当我们想要针对我们的集群执行命令时，无论是创建、编辑还是删除资源。事实上，`kubectl`也与 API 服务器通信；你可能已经注意到，在 Kubernetes 中几乎每个改变某些东西的操作基本上都是在编辑资源。如果你想要扩展或缩减你的应用程序，这将通过修改部署资源来完成。Kubernetes 将即时捕捉到变化并将其应用到资源上。此外，诸如列出 Pod 或部署的只读操作，将执行相应的`GET`请求。

实际上，如果您以更高级别的详细程度运行 kubectl 命令，例如使用`--v=6`或`--v=9`选项，您可以看到正在进行的 REST 调用。我们稍后将回到这个问题。我们可以使用 kubectl、客户端库或进行 REST 请求来访问 API。REST API 何时有用？嗯，您可以在任何编程或脚本语言中创建 REST 调用。这创造了一个全新的灵活性水平，您可以从自己的 Java 应用程序中管理 Kubernetes，从 Jenkins 中的持续交付流程中管理，或者从您正在使用的构建工具中管理，例如 Maven。可能性几乎是无限的。在本章中，我们将通过使用命令行 curl 实用程序进行 REST 调用来了解 API 概述、其结构和示例请求。本章将涵盖以下主题：

+   关于 API 版本控制的解释

+   认证（确定谁是谁）

+   授权（确定谁能做什么）

+   通过进行一些示例调用来使用 API

+   OpenAPI Swagger 文档

让我们开始 API 概述。

# API 版本控制

Kubernetes 不断发展。其功能发生变化，这也导致 API 发生变化。为了处理这些变化，并且在较长时间内不破坏与现有客户端的兼容性，Kubernetes 支持多个 API 版本，每个版本都有不同的 API 路径，例如`/api/v1`或`/apis/extensions/v1beta1`。Kubernetes API 规范中有三个 API 级别：alpha，beta 和 stable。让我们了解一下它们的区别。

# Alpha

Alpha 版本级别默认禁用，与其他软件一样，Alpha 版本应被视为有错误并且不适合生产。此外，您应该注意，Alpha 版本中引入的任何功能可能在稳定版本中并不总是可用。此外，API 的更改可能在下一个版本中不兼容。除非您非常渴望测试新功能或进行一些实验，否则不应使用`alpha`版本。

# Beta

Beta 级别与 API 的`alpha`级别完全不同，代码经过测试（仍然可能存在一些错误，因为它仍然不是`稳定`版本）。此外，与`alpha`级别相比，`beta`中的功能将不会在将来的版本中被删除。如果 API 中有破坏性的、不向后兼容的更改，Kubernetes 团队将提供迁移指南。在生产环境中使用`beta`并不是最好的主意，但您可以在非业务关键的集群上安全地使用`beta`。您也被鼓励从使用`beta`中提供反馈，这将使我们所有人使用的 Kubernetes 变得更好。`beta`级别中的版本名称将包含单词`beta`，例如`v1beta1`。

# 稳定

API 的稳定级别是经过测试的，已经准备好投入生产的软件。稳定 API 中的版本名称将是`vX`，其中`X`是一个整数，例如`v1`。

Kubernetes API 利用了 API 组的概念。引入 API 组是为了将来更容易地扩展 Kubernetes API。API 组在`REST`路径和调用的 JSON 负载的`apiVersion`字段中指定。目前，有几个 API 组正在使用：core、batch 和 extensions。组名是 API 调用的`REST`路径的一部分：`/apis/$GROUP_NAME/$VERSION`。核心组是一个例外，它不显示在`REST`路径中，例如：`/api/v1`**。**您可以在 Kubernetes API 参考中找到支持的 API 组的完整列表。

通过使用 API，您几乎可以像使用`kubectl`命令一样对集群进行任何操作。这可能是危险的；这就是为什么 Kubernetes 支持认证（确定您是谁）和授权（您可以做什么）。调用 API 服务的基本流程如下图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00106.jpg)

让我们从认证开始。

# 认证

默认情况下，Kubernetes API 服务器在两个端口上提供`HTTP`请求：

+   **本地主机**，**不安全端口**：默认情况下，IP 地址为`localhost`，端口号为`8080`。没有 TLS 通信，此端口上的所有请求都将绕过身份验证和授权插件。这是为了测试和引导，以及主节点的其他组件。这也用于其他 Kubernetes 组件，如调度程序或控制器管理器来执行 API 调用。您可以使用`--insecure-port`开关更改端口号，并使用`--insecure-bind-address`命令行开关更改默认 IP。

+   **安全端口**：默认端口号是`6443`（可以使用`--secure-port`开关进行更改），通常在云提供商上是`443`。它使用 TLS 通信。可以使用`--tls-cert-file`开关设置证书。可以使用`--tls-private-key-file`开关提供私有 SSL 密钥。通过此端口传入的所有请求将由身份验证和授权模块以及准入控制模块处理。尽可能使用安全端口。通过让 API 客户端验证`api-server`呈现的 TLS 证书，它们可以验证连接既加密又不易受中间人攻击。您还应该在仅本地主机可以访问不安全端口的情况下运行`api-server`，以便通过网络传入的连接使用`HTTP`。

+   使用 minikube 直接访问 API 服务器时，您需要使用 minikube 生成的自定义 SSL 证书。客户端证书和密钥通常存储在`~/.minikube/apiserver.crt`和`~/.minikube/apiserver.key`中。在进行`HTTP`请求时，您需要将它们加载到您的`HTTP`客户端中。如果您使用`curl`，请使用`--cert`和`--key`选项来使用`cert`和`key`文件。

API 服务器的访问可以通过代理简化，在本章后面我们将开始介绍。

如果您想从不同的域发送请求到 Kubernetes API，您需要在`api-server`上启用`cors`。您可以通过在`kube-apiserver`配置中添加`--cors-allowed-origins=["http://*"]`参数来实现。通常在`/etc/default/kube-apiserver`文件中进行配置，并重新启动`kube-apiserver`。

请注意，Kubernetes 集群不会自行管理用户。相反，用户被假定由外部独立服务管理。Kubernetes 集群中没有代表普通用户帐户的资源。这就是为什么用户不能通过 API 调用添加到集群中。

Kubernetes 不会自行管理用户帐户。

Kubernetes API 支持多种身份验证形式：`HTTP`基本身份验证、持有者令牌和客户端证书。它们被称为身份验证策略。在启动`api-server`时，您可以使用命令行标志来启用或禁用这些身份验证策略。让我们看看可能的情况，从最简单的基本身份验证策略开始。

# HTTP 基本身份验证

要使用此身份验证策略，您需要使用`--basic-auth-file=<path_to_auth_file>`开关启动`api-server`。它应该是一个包含每个用户以下条目的`csv`文件：

```
password, user name, userid

```

您还可以指定一个可选的第四列，其中包含用逗号分隔的组名。如果用户有多个组，整个列的内容必须用双引号括起来，例如：

```
password, user, userid,"group1,group2,group3"

```

如果`api-server`使用基本身份验证策略，它将期望所有的`REST`调用都包含在`Authorization`头中，其中包含用`BASE64`编码的用户名和密码（类似于普通的基本身份验证保护的 web 调用），例如：

```
BASE64ENCODED(USER:PASSWORD)

```

要生成授权头值，您可以在 shell 中使用以下命令，它将为具有密码 secret 的用户生成值：

```
echo -n "user:secret" | base64

```

请注意，对基本`auth`文件的任何更改都需要重新启动`api-server`才能生效。

在云中运行 Kubernetes 时，通常会使用`HTTP`基本身份验证作为默认。例如，一旦在 Google 容器引擎上启动容器集群，您将在 GCP 项目中的 VM 上运行`api-server`。如果运行`gcloud preview container clusters`列表，您将看到`api-server`监听请求的端点以及访问它所需的凭据。您将在第十章中找到更多关于在云中运行 Kubernetes 的内容，*在云上部署 Java 到 Kubernetes*。

# 静态令牌文件

要使`api-server`使用此方案，需要使用`--token-auth-file=<PATH_TO_TOKEN_FILE>`开关启动。与`HTTP`基本身份验证策略类似，提供的文件是一个包含每个用户记录的`csv`文件。记录需要采用以下格式：

```
token, user, userid, group

```

再次强调，组名是可选的，如果用户有多个组，您需要用逗号分隔它们并用双引号括起来。令牌只是一个`base64`编码的字符串。在 Linux 上生成令牌的示例命令可以如下：

```
$ echo `dd if=/dev/urandom bs=128 count=1 2>/dev/null | base64 | tr -d "=+/" | dd bs=32 count=1 2>/dev/null`

```

输出将是一个令牌，然后您将其输入到`token`文件中，例如：

```
3XQ8W6IAourkXOLH2yfpbGFXftbH0vn,default,default

```

当使用这种策略时，`api-server`将期望一个值为`Bearer <` `TOKEN>`的`Authorization`头。在我们的示例中，这将看起来与以下内容相同：

```
Authorization: Bearer 3XQ8W6IAourkXOLH2yfpbGFXftbH0vn

```

令牌永久有效，并且令牌列表在不重新启动 API 服务器的情况下无法更改。

# 客户端证书

为了使用这个方案，`api-server`需要使用以下开关启动：

```
--client-ca-file=<PATH_TO_CA_CERTIFICATE_FILE>

```

`CA_CERTIFICATE_FILE`必须包含一个或多个证书颁发机构，用于验证提交给`api-server`的客户端证书。客户端证书的/CN（通用名称）用作用户名。客户端证书还可以使用组织字段指示用户的组成员资格。要为用户包括多个组成员资格，您需要在证书中包括多个组织字段。例如，使用`openssl`命令行工具生成证书签名请求：

```
$ openssl req -new -key user.pem -out user-csr.pem \

-subj "/CN=user/O=group1/O=group2"

```

这将为用户名`user`创建一个证书签名请求，属于两个组`group1`和`group2`。

# OpenID

OpenID connect 1.0 是 OAuth 2.0 协议之上的一个简单身份验证层。您可以在互联网上阅读有关 OpenID connect 的更多信息，网址为`https://openid.net/connect`。它允许客户端根据授权服务器执行的身份验证来验证最终用户的身份，并以一种可互操作和类似于`REST`的方式获取有关最终用户的基本配置信息。所有云提供商，包括 Azure、Amazon 和 Google 都支持 OpenID。与`OAuth2`的主要区别在于访问令牌中返回的附加字段称为`id_token`。这个令牌是一个带有众所周知字段（例如用户的电子邮件）的**JSON Web Token**（**JWT**），由服务器签名。为了识别用户，认证器使用`OAuth2token`响应中的`id_token`作为持有者令牌。要使用 OpenID 身份验证，您需要登录到您的身份提供者，该提供者将为您提供一个`id_token`（以及标准的 OAuth 2.0 `access_token`和`refresh_token`**）**。

由于进行身份验证所需的所有数据都包含在`id_token`中，Kubernetes 不需要向身份提供者发出额外的调用。这对于可扩展性非常重要，每个请求都是无状态的。

要为`kubectl`命令提供一个令牌值，您需要使用`--token`标志。或者，您可以直接将其添加到您的`kubeconfig`文件中。

这是当您执行对您的`api-server`的`HTTP`调用时会发生的事情的简化流程：

+   `kubectl`将在`authorization`标头中发送您的`id_token`到 API 服务器。

+   API 服务器将通过检查配置中命名的证书来验证 JWT 签名

+   API 服务器将检查`id_token`是否已过期

+   API 服务器将确保用户经过授权，并且如果是这样的话会向`kubectl`返回一个响应。

默认情况下，任何具有对`api-server`的访问凭据的人都可以完全访问集群。您还可以配置更精细的授权策略，现在让我们来看看授权。

# 授权

成功验证后的下一步是检查经过授权的用户允许进行哪些操作。截至今天，Kubernetes 支持四种类型的授权策略方案。要使用特定的授权模式，启动`api-server`时使用`--authorization-mode`开关。语法是：

```
$ kube-apiserver --authorization-mode <mode>

```

`<mode>`参数包含了 Kubernetes 应该用来对用户进行身份验证的授权插件的有序列表。当启用了多个身份验证插件时，第一个成功验证请求的插件将使 Kubernetes 跳过执行所有剩余的插件。

默认授权模式是`AlwaysAllow`，允许所有请求。

支持以下授权方案：

+   基于属性的控制

+   基于角色的控制

+   Webhook

+   `AlwaysDeny`

+   `AlwaysAllow`

让我们简要地逐一描述它们。

# 基于属性的访问控制

**基于属性的访问控制**（**ABAC**）策略将在使用`--authorization-mode=ABAC`选项启动`api-server`时使用。该策略使用本地文件，您可以以灵活的方式在其中定义每个用户应具有的权限。还有一个提供策略文件的额外选项：`--authorization-policy-file`，因此使用此策略的完整语法将是：

```
$ kube-apiserver --authorization-mode=ABAC \

--authorization-policy-file=<PATH_TO_ POLICY_FILE>

```

请注意，对策略文件的任何更改都将需要重新启动`api-server`。

正如你从第七章中记得的，*Kubernetes 简介*，Kubernetes 集群使用命名空间的概念来对相关资源进行分组，如 Pod、部署或服务。`api-server`中的授权模式利用了这些命名空间。`ABAC`策略文件语法相当清晰和可读。每个条目都是描述授权规则的 JSON 对象。考虑策略文件中的以下条目，它为用户`john`提供对命名空间`myApp`的完全访问权限：

```
{

 "apiVersion": "abac.authorization.kubernetes.io/v1beta1", 

 "kind": "Policy", 

 "spec": {

 "user":"john", 

 "namespace": "myApp", 

 "resource": "*", 

 "apiGroup": "*", 

 "nonResourcePath": "*" 

 }

}

```

下一个示例将为用户`admin`提供对所有命名空间的完全访问权限：

```
{

 "apiVersion": "abac.authorization.kubernetes.io/v1beta1", 

 "kind": "Policy", 

 "spec":{

 "user":"admin", 

 "namespace": "*", 

 "resource": "*", 

 "apiGroup": "*", 

 "nonResourcePath": "*" 

 }

}

```

最后，一个示例，为所有用户提供对整个集群的只读访问权限：

```
{

 "apiVersion": "abac.authorization.kubernetes.io/v1beta1", 

 "kind": "Policy", 

 "spec": {

 "user":"*", 

 "namespace": "*", 

 "resource": "*", 

 "apiGroup": "*", 

 "nonResourcePath": "*", 

 "readonly":true 

 }

} 

```

# 基于角色的访问控制（RBAC）

**基于角色的访问控制**（**RBAC**），策略实施深度集成到了 Kubernetes 中。事实上，Kubernetes 在内部使用它来为系统组件授予必要的权限以使其正常运行。`RBAC`是 100%的 API 驱动，角色和绑定是管理员可以在集群上编写和创建的 API 资源，就像其他资源（如 Pod、部署或服务）一样。启用`RBAC`模式就像向`kube-apiserver`传递一个标志一样简单：

```
--authorization-mode=RBAC

```

这种模式允许您使用 Kubernetes API 创建和存储策略。在`RBAC` API 中，一组权限由角色的概念表示。命名空间角色和整个集群角色之间有区别，由`Role`资源表示，整个集群角色由`ClusterRole`资源表示。`ClusterRole`可以定义与`Role`相同的所有权限，但也可以定义一些与集群相关的权限，例如管理集群节点或修改所有可用命名空间中的资源。请注意，一旦启用了`RBAC`，API 的每个方面都将被禁止访问。

权限是可累加的；没有拒绝规则。

这是一个角色的示例，它为所有资源的所有操作提供了整套可用权限：

```
apiVersion: rbac.authorization.k8s.io/v1beta1

metadata:

 name: cluster-writer

rules:

 - apiGroups: ["*"]

 resources: ["*"]

 verbs: ["*"]

 nonResourceURLs: ["*"]

```

角色是一个资源，正如你从第八章中记得的，*使用 Java 与 Kubernetes*，要使用文件创建资源，你执行`kubectl create`命令，例如：

```
$ kubectl create -f cluster-writer.yml

```

`Role`和`ClusterRole`定义了一组权限，但不直接将它们分配给用户或组。在 Kubernetes API 中有另一个资源，即`RoleBinding`或`ClusterRoleBinding`。它们将`Role`或`ClusterRole`绑定到特定的主体，可以是用户、组或服务用户。要绑定`Role`或`ClusterRole`，您需要执行`kubectl create rolebinding`命令。看一下以下示例。要在命名空间`myApp`中向名为`john`的用户授予`adminClusterRole`：

```
$ kubectl create rolebinding john-admin-binding \

--clusterrole=admin --user=john --namespace=myApp

```

下一个将在整个集群中向名为`admin`的用户授予`cluster-admin ClusterRole`：

```
$ kubectl create clusterrolebinding admin-cluster-admin-binding \

--clusterrole=cluster-admin --user=admin

```

使用`kubectl create -f`的等效 YAML 文件如下：

```
apiVersion: rbac.authorization.k8s.io/v1beta1

kind: ClusterRoleBinding

metadata:

 name: admin-cluster-admin-binding

roleRef:

 apiGroup: rbac.authorization.k8s.io

 kind: ClusterRole

 name cluster-admin

subjects:

- kind: User

 name: admin

```

# WebHook

当`api-server`以`--authorization-mode=Webhook`选项启动时，它将调用外部的`HTTP`服务器来对用户进行授权。这使您能够创建自己的授权服务器。换句话说，WebHook 是一种`HTTP`回调模式，允许您使用远程`REST`服务器来管理授权，无论是您自己开发的，还是第三方授权服务器。

在进行授权检查时，`api-server`将执行`HTTP POST`请求，其中包含一个序列化的`api.authorization.v1beta1.SubjectAccessReview`对象的 JSON 有效负载。此对象描述了向`api-server`发出请求的用户，此用户想要执行的操作，以及作为此操作主题的资源的详细信息。示例请求有效负载可能如下例所示：

```
{

 "apiVersion": "authorization.k8s.io/v1beta1",

 "kind": "SubjectAccessReview",

 "spec": {

 "resourceAttributes": {

 "namespace": "rest-example",

 "verb": "get",

 "resource": "pods"

 },

 "user": "john",

 "group": [

 "group1",

 "group2"

 ]

 }

} 

```

远程授权服务器应提供响应，指示此用户是否被授权在指定资源上执行指定操作。响应应包含`SubjectAccessReviewStatus`字段，指定`api-server`是否应允许或拒绝访问。宽松的 JSON 响应看起来与此相同：

```
{

 "apiVersion": "authorization.k8s.io/v1beta1",

 "kind": "SubjectAccessReview",

 "status": {

 "allowed": true

 }

} 

```

负面响应将如下例所示出现：

```
{

 "apiVersion": "authorization.k8s.io/v1beta1",

 "kind": "SubjectAccessReview",

 "status": {

 "allowed": false,

 "reason": "user does not have read access to the namespace"

 }

}

```

将授权委托给另一个服务的可能性使授权过程非常灵活，想象一下，根据用户在企业`LDAP`目录中的角色，您自己的软件授权用户在集群中执行某些操作。

# AlwaysDeny

此策略拒绝所有请求。如果您使用`--authorization-mode=AlwaysDeny`开关启动`api-server`，则将使用它。如果您正在进行一些测试或希望阻止传入请求而不实际停止`api-server`，这可能很有用。

# AlwaysAllow

如果您使用`--authorization-mode=AlwaysAllow`开启`api-server`，则所有请求将被接受，而不使用任何授权模式。只有在不需要对 API 请求进行授权时才使用此标志。

正如您所看到的，Kubernetes 中的身份验证和授权可能性非常灵活。在本章开头的图表中，我们已经看到了 API 调用流程的第三阶段：准入控制。准入控制扮演着什么角色？让我们找出来。

# 准入控制

准入控制插件在请求经过身份验证和授权后，但在对 API 资源进行任何更改之前拦截对 Kubernetes API 服务器的请求。这些插件按顺序运行，在请求被接受到集群之前运行。Kubernetes API 服务器支持一个标志`admission-control`，它接受一个逗号分隔的有序准入控制插件列表。

现在我们已经了解了 API 调用的外观，让我们实际利用一些。

# 使用 API

API 参考是一份详细的文档，可以在互联网上找到[`kubernetes.io/docs/api-reference/v1.6/`](https://kubernetes.io/docs/api-reference/v1.6/)；[当然，API 版本将来会更改，`v1.6`是写作时的当前版本。](https://kubernetes.io/docs/api-reference/v1.6/)

在我们对`api-server`进行一些实际调用之前，值得知道`kubectl`也使用 API 与 Kubernetes 集群进行通信。正如我们之前提到的，您可以通过`kubectl`命令查看正在进行的`REST`调用。查看在使用`kubectl`时发送到服务器的内容是熟悉 Kubernetes API 的好方法。

要查看`kubectl`执行的`REST`请求，可以以更高的详细级别运行它，例如使用`--v=6`或`--v=9`选项。

在我们开始实际进行`REST`调用之前，让我们简要地看一下 API 操作有哪些可能。

# API 操作

Kubernetes API 定义了 CRUD（创建、更新、读取和删除）一组操作：

+   `Create`：创建操作将在集群中创建资源。您需要在您的`REST`调用中提供的 JSON 有效负载是资源清单。这相当于我们在第八章中构建的 YAML 文件，*使用 Java 与 Kubernetes*。这次，它将以 JSON 格式呈现。

+   `Update`：更新操作可以是`Replace`或`Patch`。`Replace`将简单地用提供的规范替换整个资源对象（例如 Pod）。另一方面，`Patch`将仅对特定字段应用更改。

+   `Read`：读取操作可以是`Get`、`List`或`Watch`。通过执行`Get`，您将得到一个特定资源对象的名称。执行`List`将检索命名空间内特定类型的所有资源对象。您可以使用选择器查询。`List`操作的一种特殊形式是`List All Namespaces`，正如其名称所示，这将检索所有命名空间中的资源。`Watch`操作将流式传输对象或列表对象的结果，因为它们被更新。

+   删除：将简单地删除资源。

Kubernetes `api-server`还公开了一些其他特定于资源的操作。这包括`Rollback`，它将 Pod 模板回滚到先前的版本，或者读取/写入规模，它读取或更新给定资源的副本数量。

# 示例调用

在以下示例中，我们将使用命令行`HTTP`客户端`curl`。您不限于`curl`，可以自由使用您觉得方便的`HTTP`客户端。使用带有用户界面的`HTTP`客户端通常非常方便，它们通常以结构化形式呈现`HTTP`响应，并有时还会进行一些请求验证，如果它是格式良好的。我推荐的 GUI 客户端将是 Postman（适用于 Windows、Linux 或 Mac），或者 Mac 的 PAW。

在进行任何调用之前，让我们首先启动一个代理到 Kubernetes API 服务器。首先需要配置`kubectl`，以便能够与您的集群通信。在我们的本地 Kubernetes 安装中，使用`minikube`，`kubectl`命令将自动配置。要启动到`api-server`的代理，请执行以下命令：

```
$ kubectl proxy --port=8080

```

在代理会话运行时，发送到`localhost:8000`的任何请求将被转发到 Kubernetes API 服务器。要检查我们的`api-server`是否正在运行，让我们询问它支持的 API 版本：

```
$ curl http://localhost:8080/api/

```

如果`api-server`正在运行并等待传入请求，它应该给您一个类似于这样的输出：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00107.jpg)

看起来一切都很顺利；让我们继续利用暴露的 API，开始创建服务，与之前一样。

# 使用 API 创建服务

首先，让我们创建一个服务清单文件。请注意，如果您在第八章中使用`kubectl`创建了您的服务、部署和 Pod，*使用 Java 与 Kubernetes*，您将需要使用`kubectl`或 Kubernetes 仪表板将它们删除。我们将使用相同的名称来创建服务和部署。在使用`curl`发送较大有效负载时，最好将有效负载放在外部文件中，而不是在命令行中输入。我们将使用的 JSON 文件作为有效负载与我们使用`kubectl`创建 Pod 时使用的文件非常相似，但这次是以 JSON 格式。让我们创建一个名为`service.json`的文件：

```
{

 "apiVersion": "v1",

 "kind": "Service",

 "metadata": {

 "name": "rest-example",

 "labels": {

 "app": "rest-example",

 "tier": "backend"

 }

 },

 "spec": {

 "type": "NodePort",

 "ports": [

 {

 "port": 8080

 }

 ],

 "selector": {

 "app": "rest-example",

 "tier": "backend"

 }

 }

} 

```

请注意，JSON 文件的内容基本上与我们在使用 YAML 文件创建资源时使用的内容相同。是的，您可以清楚地看到`kubectl`命令是如何实现的，它只是从文件输入创建一个 JSON 有效负载，一点魔术都没有。

您可以在网上使用其中一个 YAML/JSON 转换器在 YAML 和 JSON 之间进行转换。Kubernetes `api-server`将接受这样的 JSON，就像`Kubectl`接受 YAML 文件一样。

准备好我们的 JSON 文件，下一步是通过调用以下命令在我们的集群中创建服务资源：

```
$ curl -s http://localhost:8080/api/v1/namespaces/default/services \

-XPOST -H 'Content-Type: application/json' -d@service.json

```

定义了我们的服务，让我们创建一个部署。

# 使用 API 创建部署

创建部署与创建服务非常相似，毕竟它是创建另一种类型的 Kubernetes 资源。我们所需要的只是一个适当的 JSON 有效负载文件，我们将使用`POST HTTP`方法将其发送到`api-server`。我们的 JSON 格式的`rest-example`部署清单可以如下所示：

```
{

 "apiVersion": "extensions/v1beta1",

 "kind": "Deployment",

 "metadata": {

 "name": "rest-example"

 },

 "spec": {

 "replicas": 1,

 "template": {

 "metadata": {

 "labels": {

 "app": "rest-example",

 "tier": "backend"

 }

 },

 "spec": {

 "containers": [

 {

 "name": "rest-example",

 "image": "jotka/rest-example",

 "imagePullPolicy": "IfNotPresent",

 "resources": {

 "requests": {

 "cpu": "100m",

 "memory": "100Mi"

 }

 },

 "env": [

 {

 "name": "GET_HOSTS_FROM",

 "value": "dns"

 }

 ],

 "ports": [

 {

 "containerPort": 8080

 }

 ]

 }

 ]

 }

 }

 }

}

```

让我们使用`deployment.json`文件名保存文件。再次，我们现在需要做的就是将这个文件发布到`api-server`。这个过程与创建服务非常相似，只是向不同的端点发送不同的有效负载进行`POST`。要使用`curl`从 shell 创建部署，请执行以下命令：

```
$ curl -s \ http://localhost:8080/apis/extensions/v1beta1/namespaces/default/deployments -XPOST -H 'Content-Type: application/json' \

-d@deployment.json

```

在前面的示例中，您应该注意到与部署相关的 API 命令位于另一个 API 组：`extensions`。这就是为什么端点将具有不同的`REST`路径。

执行这两个`REST HTTP`请求后，我们应该在集群中创建了我们的服务和部署。当然，因为部署清单包含副本数为`1`，一个 Pod 也将被创建。让我们通过执行以下命令来检查是否属实：

```
$ kubectl get services

$ kubectl get deployments

$ kubectl get pods

```

正如您在以下截图中所看到的，所有资源都存在于我们的集群中。然而，这一次，它们是通过两个简单的`HTTP POST`请求到 Kubernetes `api-servers`创建的，而不是使用`kubectl`：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00108.jpg)

我们之前说过，我们可以观察`kubectl`工具执行的`HTTP`请求。让我们验证一下。我们将执行最后一个命令以获取 Pod 的列表，但使用相同的额外详细级别，就像这样：

```
$ kubectl get pods -v6

```

输出应该类似于以下内容：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00109.jpg)

有一堆关于从集群缓存获取信息的日志行，但最后一行特别有趣，它包含了`kubectl`正在进行的实际`HTTP`请求：

```
GET https://192.168.99.100:8443/api/v1/namespaces/default/pods

```

如果您现在使用此 URL 运行`curl GET`命令，所有身份验证和授权机制都会生效。但是通过运行`api-server`代理，我们可以通过在代理端口上执行调用来跳过授权和身份验证（请注意，`curl`默认执行`GET`方法）：

```
$ curl http://localhost:8080/api/v1/namespaces/default/pods

```

作为输出，您将获得包含有关集群中 Pod 的详细信息的 JSON 响应。API 正在工作，正如您在以下截图中所看到的：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00110.jpg)

# 删除服务和部署

如果您决定进行一些清理工作，您可以通过执行`HTTP DELETE`请求来删除服务和部署，例如：

```
$ curl http://localhost:8000/ \ apis/extensions/v1beta1/namespaces/default/deployments/rest-example \ 

-XDELETE

$ curl http://localhost:8080/ \ api/v1/namespaces/default/services/rest-example -XDELETE

```

通过查看 Web 文档或窥探`kubectl`调用的 URL 来找到正确的 API 操作`REST`路径（端点）可能非常不方便。有一种更好的方法；Kubernetes `api-server`的 OpenAPI 规范。让我们看看如何获取这个规范。

# Swagger 文档

Kubernetes 的`api-server`利用 OpenAPI 规范提供了可用 API 命令的列表。OpenAPI 规范定义了一种标准的、与语言无关的 REST API 接口，允许人类和计算机在没有访问源代码、文档或通过网络流量检查的情况下发现和理解服务的能力。使用随 Kubernetes`api-server`一起提供的 SwaggerUI 工具浏览 API 命令目录非常方便。您也可以使用 SwaggerUI 执行 HTTP 命令。

请注意，如果您正在使用 Minikube 运行本地集群，默认情况下未启用 SwaggerUI。您需要在集群启动期间使用以下命令启用它：

```
$ minikube start --extra-config=apiserver.Features.EnableSwaggerUI=true

```

在端口`8080`上仍在运行`api-server`代理的情况下，访问以下主机在您的 Web 浏览器中查看 SwaggerUI 屏幕：

```
http://localhost:8080/swagger-ui/

```

您将看到一个可用 API 命令的列表，分组为 API 组：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00111.jpg)

展开每个 API 部分将为您提供所有可用的端点以及每个操作的描述。SwaggerUI 是一个探索 API 的清晰可读形式的绝佳工具。

# 摘要

正如您所看到的，Kubernetes 公开的 API 是您工具库中非常强大的工具。可以通过仪表板或`kubectl`客户端执行的任何任务都作为 API 公开。您可以通过使用`HTTP`调用简单地执行集群中的几乎任何操作。Kubernetes 采用 API 优先的方法，使其可编程和可扩展。正如我们所看到的，使用 API 很容易入门。我们的服务和部署创建示例可能很简单，但应该让您了解如何使用`api-server`进行实验。使用 API，您不仅可以从命令行使用`kubectl`，还可以从您自己的应用程序、构建脚本或持续交付流水线中创建和检索集群资源。只有您的想象力和天空是极限，说到天空，现在是时候移动到那里，看看 Kubernetes 如何在云中使用了。


# 第十章：在云中部署 Java 在 Kubernetes 上

在之前的章节中，我们已经成功在本地运行了 Kubernetes 集群。使用`minikube`是学习 Kubernetes 和在自己的机器上进行实验的好方法。由`minikube`支持的集群的行为与在服务器上运行的普通集群完全相同。然而，如果您决定在生产环境中运行集群软件，云是最佳解决方案之一。在本章中，我们将简要介绍在 Docker 上运行微服务的情况下使用云环境的优势。接下来，我们将在 Amazon AWS 上部署我们的 Kubernetes 集群。配置 AWS 并在其上运行 Kubernetes 并不是从一开始就最简单和直接的过程，但是，遵循本章将为您提供一个过程概述，您将能够快速运行自己的云集群，并在其上部署自己或第三方的 Docker 镜像。

涵盖的主题列表包括：

+   使用云、Docker 和 Kubernetes 的好处

+   安装所需工具

+   配置 AWS

+   部署集群

让我们从使用云部署的 Kubernetes 集群的优势开始。

# 使用云、Docker 和 Kubernetes 的好处

在 Kubernetes 集群上部署应用程序有其优势。它具有故障弹性、可扩展性和高效的架构。拥有自己的基础设施和使用云有什么区别？嗯，这归结为几个因素。首先，它可以显著降低成本。对于小型服务或应用程序，当不使用时可以关闭，因此在云中部署应用程序的价格可能更低，由于硬件成本更低，将更有效地利用物理资源。您将不必为不使用计算能力或网络带宽的节点付费。

拥有自己的服务器需要支付硬件、能源和操作系统软件的费用。Docker 和 Kubernetes 是免费的，即使用于商业目的；因此，如果在云中运行，云服务提供商的费用将是唯一的成本。云服务提供商经常更新其软件堆栈；通过拥有最新和最好的操作系统软件版本，您可以从中受益。

在计算能力或网络带宽方面，像亚马逊或谷歌这样的大型云提供商很难被击败。他们的云基础设施非常庞大。由于他们为许多不同的客户提供服务，他们购买大型高性能系统，其性能水平远高于小公司内部运行的水平。此外，正如您将在本章的后续部分中看到的，云提供商可以在几分钟甚至几秒钟内启动新的服务器或服务。因此，如果有需要，新的实例将以几乎对软件用户透明的方式被带到生活中。如果您的应用程序需要处理大量请求，有时在云中部署它可能是唯一的选择。

至于容错性，因为云提供商将其基础设施分布在全球各地（例如 AWS 区域，您将在本章后面看到），您的软件可以是无故障的。没有任何单一事故，如停电、火灾或地震，可以阻止您的应用程序运行。将 Kubernetes 加入到方程式中可以扩展部署的规模，增加应用程序的容错性，甚至将完全失败的机会降低到零。

让我们将软件移到云端。为此，我们需要先创建一个工具集，安装所需的软件。

# 安装工具

要能够在 Amazon EC2 上管理 Kubernetes 集群，我们需要先安装一些命令行工具。当然，也可以使用 Amazon EC2 的 Web 界面。启动集群是一个相当复杂的过程；您需要一个具有适当访问权限和权限的用户，用于集群状态的存储，运行 Kubernetes 主节点和工作节点的 EC2 实例等。手动完成所有操作是可能的，但可能会耗时且容易出错。幸运的是，我们有工具可以自动化大部分工作，这将是 AWS 命令行客户端（`awscli`）和`kops`，Kubernetes 操作，生产级 K8s 安装，升级和管理。不过有一些要求。`Kops`在 Linux 和 macOS 上运行，它是用 Go 编写的，就像 Docker 一样。`awscli`是用 Python 编写的，所以让我们先专注于 Python 安装。

# Python 和 PIP

运行 AWS 命令行工具（`awscli`），我们需要在我们的机器上安装`python3`。

它可能已经存在，您可以使用以下命令进行验证：

```
$ python3 --version

```

如果输出是`command not found`，最快的安装方法将是使用系统上的软件包管理器，例如 Debian/Ubuntu 上的`apt`，Fedora 上的`yum`，或 macOS 上的 Homebrew。如果您在 macOS 上工作并且尚未安装 Homebrew，我强烈建议您这样做；它是一个很棒的工具，可以让您轻松安装成千上万的软件包以及所有所需的依赖项。Homebrew 可以免费获取[`brew.sh/`](https://brew.sh/)。要安装它，请执行以下命令：

```
$ ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"

```

从现在开始，您应该在 macOS 终端中可以使用`brew`命令。

要在 Linux 上使用`apt`软件包管理器（在 Debian 或 Ubuntu 上）安装 Python，请执行以下命令：

```
$ sudo apt-get update

$ sudo apt-get install python3.6

```

在 macOS 上，这将是以下命令：

```
$ brew install python3

```

安装 Python 的过程取决于您的计算机速度和互联网连接速度，但不应该花费太长时间。一旦安装了 Python，我们将需要另一个工具，即`pip`。`pip`是安装 Python 软件包的推荐工具。它本身是用 Python 编写的。您可以使用您选择的软件包管理器来安装它，例如在 Ubuntu 或 Debian 上执行以下命令：

```
$ sudo apt-get install python3-pip

```

安装`pip`的另一种方法是使用安装脚本。在这种情况下，Linux 和 macOS 的过程完全相同。首先，我们需要使用以下命令下载安装脚本：

```
$ curl -O https://bootstrap.pypa.io/get-pip.py

```

过一段时间，我们需要通过执行以下命令运行安装脚本：

```
$ python3 get-pip.py -user

```

过一段时间，`pip`应该可以在终端 shell 中使用。要验证它是否正常工作，请执行以下命令：

```
$ pip -V

or 

$ pip --version

```

现在我们已经安装并正常运行 Python 和 pip，是时候转向更有趣的事情了，安装 Amazon AWS 命令行工具。

# AWS 命令行工具

Amazon **AWS 命令行工具**（**awscli**）界面是管理 AWS 服务的统一工具。`awscli`是建立在 AWS SDK for Python 之上的，它提供了与 AWS 服务交互的命令。只需进行最小配置（实际上，提供登录 ID 和密码就足够了，我们马上就会做），您就可以开始使用 AWS 管理控制台 Web 界面提供的所有功能。此外，`awscli`不仅仅是关于 EC2，我们将用它来部署我们的集群，还涉及其他服务，例如 S3（存储服务）。

要安装`awscli`，执行以下`pip`命令：

```
$ pip3 install --user --upgrade awscli

```

过一会儿，`pip`将在驱动器的`python3`文件夹结构中下载并安装必要的文件。在 macOS 和 Python 3.6 的情况下，它将是`~/Library/Python/3.6/bin`。将此文件夹添加到您的`PATH`环境变量中非常方便，以便在 shell 中的任何位置都可以使用。这很简单；您需要编辑其中一个文件中的`PATH`变量，具体取决于您使用的 shell：

+   **Bash**：`.bash_profile`、`.profile`或`.bash_login`

+   **Zsh**：`.zshrc`

+   **Tcsh**：`.tcshrc`、`.cshrc`或`.login`

在 macOS 上，`PATH`条目可能看起来与此相同：

```
export PATH=~/Library/Python/3.6/bin/:$PATH

```

重新登录或启动新的终端后，您可以通过执行以下命令来验证`aws`命令是否可用：

```
$ aws -version

```

正如您在输出中所看到的，这将为您提供详细的`aws`命令行工具版本，还有它运行的 Python 版本：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00112.jpg)

`awscli`已准备就绪，但我们还有一个工具要添加到我们的工具设置中。这将是 Kubernetes `kops`。

# Kops

Kubernetes 操作或简称`kops`是生产级 Kubernetes 安装、升级和管理工具。它是一个命令行实用程序，可帮助您在 AWS 上创建、销毁、升级和维护高可用的 Kubernetes 集群。该工具官方支持 AWS。您可以在 GitHub 上找到`kops`的发布版本：[`github.com/kubernetes/kops/releases`](https://github.com/kubernetes/kops/releases)

要在 macOS 或 Linux 上安装，您只需要下载二进制文件，更改权限为可执行，然后就完成了。例如，要下载，请执行：

```
$ wget \ https://github.com/kubernetes/kops/releases/download/1.6.1/kops-darwin-amd64 

$ chmod +x kops-darwin-amd64

$ mv kops-darwin-amd64 /usr/local/bin/kops

```

或者，如果您使用 Linux，请执行以下命令：

```
$ wget \ https://github.com/kubernetes/kops/releases/download/1.6.2/kops-linux-amd64

$ chmod +x kops-linux-amd64

$ mv kops-linux-amd64 /usr/local/bin/kops

```

另外，再次使用软件包管理器将是获取最新的`kops`二进制文件的最简单方法，例如在 macOS 上使用`brew`：

```
$ brew update && brew install kops

```

请注意，您必须安装`kubectl`（[`kubernetes.io/docs/tasks/tools/install-kubectl/`](https://kubernetes.io/docs/tasks/tools/install-kubectl/)）才能使`kops`正常工作。如果您使用软件包管理器，`kubectl`的依赖关系可能已经在`kops`软件包中定义，因此将首先安装`kubernetes-cli`。

最后一个工具是`jq`。虽然不是强制性的，但在处理 JSON 数据时非常有用。所有 AWS、Kubernetes 和`kops`命令都将发布和接收 JSON 对象，因此安装`jq`工具非常方便，我强烈建议安装`jq`。

# jq

`jq`是一个命令行 JSON 处理器。它的工作原理类似于 JSON 数据的`sed`；您可以使用它来过滤、解析和转换结构化数据，就像`sed`、`awk`或`grep`让您处理原始文本一样容易。`Jq`可在 GitHub 上找到[`stedolan.github.io/jq/`](https://stedolan.github.io/jq/)。安装非常简单；它只是一个单一的二进制文件，适用于 Windows、macOS 和 Linux。只需下载它并将其复制到系统`PATH`上可用的文件夹中，以便能够从 shell 或命令行中运行它。

假设在开始使用 kops 之前我们已经安装了所有工具，我们需要首先配置我们的 AWS 账户。这将创建一个管理员用户，然后使用`aws`命令行工具创建用于运行`kops`的用户。

# 配置 Amazon AWS

在设置 Kubernetes 集群之前，AWS 的配置基本上是创建一个用户。所有其他工作将由`kops`命令更多或更少地自动完成。在我们可以从命令行使用`kops`之前，最好有一个专门用于`kops`的用户。但首先，我们需要创建一个管理员用户。我们将从 Web 管理控制台进行操作。

# 创建一个管理员用户

根据您选择的 AWS 区域，AWS 管理控制台可在`console.aws.amazon.com`的子域上使用，例如[`eu-central-1.console.aws.amazon.com`](https://eu-central-1.console.aws.amazon.com)。登录后，转到安全、身份和合规性部分的 IAM 页面，然后切换到用户页面，然后单击“添加用户”按钮。

您将看到用户创建屏幕：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00113.jpg)

我们将需要这个用户来使用`awscli`，所以我们需要标记的唯一选项是程序化访问。单击“下一步：权限”，让我们通过将其添加到`admin`组来为我们的`admin`用户提供完整的管理权限。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00114.jpg)

在用户创建向导的最后一页，您将能够看到访问密钥 ID 和秘密访问密钥 ID。不要关闭页面，我们将在短时间内需要两者来使用`awscli`进行身份验证：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00115.jpg)

就是这样。我们已经创建了一个具有所有管理权限的管理员用户，并获得了访问密钥。这就是我们使用`awscli`管理 AWS 实例所需要的一切。使用`admin`用户运行`kops`可能不是最好的主意，所以让我们为此创建一个单独的用户。然而，这次我们将从命令行进行操作。与在 Web 控制台上点击 UI 相比，这将更加容易。首先，让我们使用管理员用户的 Access Key ID 和`Secret access key ID`进行身份验证，这些信息显示在用户创建向导的最后一页上。

# 为 kops 创建用户

`kops`用户需要在 AWS 中具有以下权限才能正常运行：

+   `AmazonEC2FullAccess`

+   `AmazonS3FullAccess`

+   `AmazonRoute53FullAccess`

+   `IAMFullAccess`

+   `AmazonVPCFullAccess`

首先，我们将创建一个名为`kops`的组，并为该组分配所需的权限。执行以下命令列表来创建一个组并分配权限：

```
$ aws iam create-group --group-name kops

$ aws iam attach-group-policy --policy-arn $ arn:aws:iam::aws:policy/AmazonEC2FullAccess --group-name kops

$ aws iam attach-group-policy --policy-arn arn:aws:iam::aws:policy/AmazonS3FullAccess --group-name kops

$ aws iam attach-group-policy --policy-arn arn:aws:iam::aws:policy/AmazonRoute53FullAccess --group-name kops

$ aws iam attach-group-policy --policy-arn arn:aws:iam::aws:policy/IAMFullAccess --group-name kops

$ aws iam attach-group-policy --policy-arn arn:aws:iam::aws:policy/AmazonVPCFullAccess --group-name kops

```

`create-group`命令将给您一些 JSON 响应，但是如果一切顺利，当将权限（组策略）附加到组时将不会有响应：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00116.jpg)

接下来，让我们创建`kops` IAM 用户并将用户添加到`kops`组，使用以下命令：

```
$ aws iam create-user --user-name kops

$ aws iam add-user-to-group --user-name kops --group-name kops

```

如果您感兴趣，现在可以登录到 Web AWS 控制台。您会看到我们的`kops`用户拥有我们需要的所有权限：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00117.jpg)

要列出所有注册用户，请执行以下命令：

```
$ aws iam list-users 

```

正如您在以下截图中所看到的，我们现在应该有两个用户：`admin`和`kops`：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00118.jpg)

关于我们的新`kops`用户，我们需要做的最后一件事就是生成访问密钥。我们将需要它们来使用`aws configure`命令进行身份验证。执行以下操作为`kops`用户生成访问密钥：

```
$ aws iam create-access-key --user-name kops

```

正如您在以下截图中所看到的，AWS 将以包含`AccessKeyId`和`SecretAccessKey`的 JSON 响应进行回答；在使用`aws configure`命令进行身份验证时，我们将需要这两者：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00119.jpg)

现在我们需要做的就是使用`aws configure`命令进行身份验证，提供我们在响应中获得的`AccessKeyId`和`SecretAccessKey`。执行以下操作：

```
$ aws configure 

```

因为`aws configure`命令不会为`kops`导出这些变量以供使用，所以我们现在需要导出它们：

```
$ export AWS_ACCESS_KEY_ID=<access key>

$ export AWS_SECRET_ACCESS_KEY=<secret key>

```

就是这样，我们已经使用名为`kops`的新用户进行了身份验证，该用户具有启动 Kubernetes 集群所需的所有权限。从现在开始，我们执行的每个`kops`命令都将使用 AWS `kops`用户。现在是时候回到重点并最终创建我们的集群了。

# 创建集群

我们将创建一个包含一个主节点和两个工作节点的简单集群。要使用`kops`进行操作，我们需要：

+   用户配置文件在`~/.aws/credentials`中声明（如果您使用`aws configure`进行身份验证，则会自动完成）。

+   用于存储`kops`集群状态的 S3 存储桶。为了存储我们集群及其状态的表示，我们需要创建一个专用的 S3 存储桶供`kops`使用。这个存储桶将成为我们集群配置的真相来源。

+   已配置 DNS。这意味着我们需要在同一 AWS 账户中拥有一个 Route 53 托管区域。Amazon Route 53 是一个高可用性和可扩展的云**域名系统**（**DNS**）网络服务。Kops 将使用它来创建集群所需的记录。如果您使用更新的 kops（1.6.2 或更高版本），则 DNS 配置是可选的。相反，可以轻松地创建一个基于 gossip 的集群。为了简单起见，我们将使用基于 gossip 的集群。为了使其工作，集群名称必须以`k8s.local`结尾。让我们看看关于 DNS 设置的其他选项。

# DNS 设置

基本上，我们的集群域名有四种可能的情况：托管在 AWS 上的根域，托管在 AWS 上的域的子域，在其他地方托管的域使用亚马逊 Route 53，最后，在 Route 53 中设置集群的子域，同时在其他地方设置根域。现在让我们简要地看一下这些设置。

# 托管在 AWS 上的根域

如果您在 AWS 上购买并托管了您的域名，那么您可能已经自动配置了 Route 53。如果您想要使用此根级域名用于您的集群，您无需做任何操作即可使用该域名与您的集群。

# 托管在 AWS 上的域的子域

如果您在 AWS 上购买并托管了您的域名，但想要将子域用于集群，您需要在 Route 53 中创建一个新的托管区域，然后将新路由委派给这个新区域。基本上就是将您的子域的 NS 服务器复制到 Route 53 中的父域。假设我们的域是[mydomain.com](http://www.mydomain.com/)；我们首先需要获取一些信息。请注意，当执行`aws`命令时，现在`jq`命令行工具非常方便。首先，我们需要我们主要父区域的 ID：

```
$ aws route53 list-hosted-zones | jq '.HostedZones[] \ 

| select(.Name=="mydomain.com.") | .Id'

```

要创建新的子域，请执行以下操作：

```
$ aws route53 create-hosted-zone --name myservice.mydomain.com \ 

--caller-reference $ID | jq .DelegationSet.NameServers

```

请注意，上一个命令将列出新域的名称服务器。如果您之前创建了子域，并且想要列出名称服务器（以便首先将 NS 服务器列表复制到父区域，我们需要知道它们），请执行以下命令以获取子域区域 ID：

```
$ aws route53 list-hosted-zones | jq '.HostedZones[] | \ select(.Name==" myservice.mydomain.com.") | .Id'

```

有了子域区域的 ID，我们可以通过执行以下命令列出其名称服务器：

```
$ aws route53 get-hosted-zone --id <your-subdomain-zoneID> \

| jq .DelegationSet.NameServers

```

到目前为止，我们有父区域的区域 ID，子域区域的 ID 和子域名称服务器列表。我们准备好将它们复制到父区域中了。最方便的方法是准备 JSON 文件，因为输入内容相当长。文件将如下所示：

```
{

 "Changes": [

 {

 "Action": "CREATE",

 "ResourceRecordSet": {

 "Name": "myservice.mydomain.com",

 "Type": "NS",

 "TTL": 300,

 "ResourceRecords": [

 {

 "Value": "ns-1.awsdns-1.com"

 },

 {

 "Value": "ns-2.awsdns-2.org"

 },

 {

 "Value": "ns-3.awsdns-3.com"

 },

 {

 "Value": "ns-4.awsdns-4.net"

 }

 ]

 }

 }

 ]

}

```

您需要将此保存为文件，比如`my-service-subdomain.json`，并执行最后一个命令。它将把名称服务器列表复制到父区域中。

```
$ aws route53 change-resource-record-sets 

--change-batch file://my-service-subdomain.json \

--hosted-zone-id <your-parent-zone-id>

```

一段时间后，所有发送到`*.myservice.mydomain.com`的网络流量将被路由到 AWS Route 53 中正确的子域托管区域。

# 使用另一个注册商购买的域名的 Route 53

如果您在其他地方购买了域名，并且想要将整个域专用于您的 AWS 托管集群，情况可能会有些复杂，因为此设置要求您在另一个域名注册商处进行重要更改。

如果您的域名注册商也是域名的 DNS 服务提供商（实际上，这种情况非常常见），建议在继续域名注册转移过程之前将您的 DNS 服务转移到 Amazon Route 53。

这样做的原因是，当您转移注册时，之前的注册商可能会在他们收到来自 Route 53 的转移请求后禁用该域的 DNS 服务。因此，您在该域上拥有的任何服务，如 Web 应用程序或电子邮件，可能会变得不可用。要将域注册转移到 Route 53，您需要使用 Route 53 控制台，该控制台位于[`console.aws.amazon.com/route53/`](https://console.aws.amazon.com/route53/)。在导航窗格中，选择 Registered Domains，然后选择 Transfer Domain，并输入您想要转移的域的名称，然后单击 Check。如果该域不可转移，控制台将列出可能的原因以及处理它们的推荐方法。如果一切正常并且该域可以转移，您将有选项将其添加到购物车中。然后，您需要输入一些详细信息，例如您的联系信息，用于转移的授权代码（您应该从之前的注册商那里获取），以及名称服务器设置。我强烈建议选择 Route 63 托管的 DNS 服务器，因为它非常容易配置且可靠。Route 63 将负责与您之前的注册商进行通信，但您可能会收到一些需要确认的电子邮件。转移过程可能需要更长的时间，但完成后，您可以继续以与前两种情况相同的方式配置基于 AWS 的集群的域。

# AWS Route 53 中集群的子域，域名在其他地方

如果您在亚马逊以外的注册商那里注册了您的域，并且想要使用该域的子域指向您的集群，您需要修改您注册商中的名称服务器条目。这将需要在 Route 53 中创建一个新的托管区子域，然后将该子域的名称服务器记录迁移到您的注册商。

与托管在 AWS 上的域上的子域类似，让我们首先创建一个子域，通过执行以下命令：

```
$ aws route53 create-hosted-zone \

--name myservice.mydomain.com \

--caller-reference $ID | jq .DelegationSet.NameServers

```

上一个命令的输出将列出子域的名称服务器。您需要登录到您的注册商设置页面，并创建一个新的子域，提供从上一个命令中收到的四个名称服务器记录。您可以在您特定的注册商帮助指南中找到有关如何编辑您域的名称服务器的详细说明。

之前的指南应该使您的集群在特定域或子域下可用。然而，在本章的其余部分，我们将运行基于流言的集群。

在 AWS 上创建任何内容之前，我们必须查看可用的区域。您应该知道，Amazon EC2 托管在全球多个位置。这些位置由区域和可用区组成。每个区域是一个单独的地理区域。每个区域都有多个隔离的位置，称为可用区。您可以选择您想要的位置，但首先，您需要检查可用的区域。现在让我们这样做。

# 检查区域的可用性

要列出特定区域可用的区域，请执行以下命令：

```
$ aws ec2 describe-availability-zones --region eu-central-1

```

如您在以下截图中所见，AWS 将在响应中列出可用的区域：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00120.jpg)

# 创建存储

我们的集群需要在某个地方存储其状态。Kops 使用 Amazon S3 存储桶来实现这一目的。S3 存储桶是**Amazon Web Services**（**AWS**）对象存储服务**Simple Storage Solution**（**S3**）中的逻辑存储单元。存储桶用于存储对象，对象由描述数据的数据和元数据组成。要创建一个存储桶，请执行以下`aws`命令：

```
$ aws s3api create-bucket \

--bucket my-cluster-store \

--region eu-central-1 \

--create-bucket-configuration LocationConstraint=eu-central-1

```

如您在以下截图中所见，AWS 将向您提供有关存储位置的简明信息：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00121.jpg)

创建存储后，我们需要在创建集群时使其对`kops`可用。为此，我们需要将存储桶的名称导出到`KOPS_STATE_STORE`环境变量中：

```
$ export KOPS_STATE_STORE=s3://my-cluster-store

```

我们现在准备创建一个集群。

在你记得的时候，我们将使用基于流言的集群，而不是配置的 DNS，因此名称必须以`k8s.local`结尾。

# 创建一个集群

首先将我们的集群名称导出到环境变量中。这将很有用，因为我们经常会引用集群的名称。执行以下命令导出集群名称：

```
$ export NAME=my-rest-cluster.k8s.local

```

`kops create cluster`是我们将用来创建集群的命令。请注意，这不会影响我们的 Amazon EC2 实例。该命令的结果只是一个本地集群模板，我们可以在在 AWS 上进行真正的物理更改之前进行审查和编辑。

命令的语法非常简单：

```
$ kops create cluster [options]

```

该命令有很多选项；您可以在 GitHub 上始终找到最新的描述，网址为[`github.com/kubernetes/kops/blob/master/docs/cli/kops_create_cluster.md`](https://github.com/kubernetes/kops/blob/master/docs/cli/kops_create_cluster.md) 。让我们专注于最重要的几个：

| **选项** | **描述** |
| --- | --- |
| `--master-count [number]` | 设置主节点的数量。默认值是每个主区域一个主节点。 |
| `--master-size [string]` | 设置主节点的实例大小，例如：`--master-size=t2.medium` 。 |
| `--master-volume-size [number]` | 设置主节点实例卷大小（以 GB 为单位）。 |
| `--master-zones [zone1,zone2]` | 指定要运行主节点的 AWS 区域（这必须是奇数）。 |
| `--zones [zone1,zone2 ]` | 用于运行集群的区域，例如：`--zones eu-central-1a,eu-central-1b` 。 |
| `--node-count [number]` | 设置节点的数量。 |
| `--node-size [string]` | 设置节点的实例大小，例如：`--node-size=t2.medium` 。 |
| `--node-volume-size int32` | 设置节点的实例卷大小（以 GB 为单位）。 |

如果您想将您的集群设置为私有的（默认情况下是公共的），您还需要考虑使用以下选项：

| **选项** | **描述** |
| --- | --- |
| `--associate-public-ip [true&#124;false]` | 指定是否要为您的集群分配公共 IP。 |
| `--topology [public&#124;private]` | 指定集群的内部网络拓扑，可以是`public`或`private`。 |
| `--bastion` | `--bastion`标志启用了一个堡垒实例组。该选项仅适用于私有拓扑。它将为集群实例的 SSH 访问生成一个专用的 SSH 跳转主机。跳转主机提供了进入集群私有网络的入口点。它可以启动和停止，以启用或禁用来自互联网的入站 SSH 通信。 |

现在让我们使用以下命令创建我们的集群：

```
$ kops create cluster --v=0 \

--cloud=aws --node-count 2 \

--master-size=t2.medium \

--master-zones=eu-central-1a \

--zones eu-central-1a,eu-central-1b  \

--name=${NAME} \

--node-size=t2.medium

```

在响应中，`kops`将列出已创建的配置的所有细节，并建议您可以采取的新集群配置的一些下一步操作：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00122.jpg)

运行命令后，`kops`将配置您的`kubectl` Kubernetes 客户端指向您的新集群；在我们的示例中，这将是`my-rest-cluster.k8s.local`。

正如我们之前所说，在这个阶段，只创建了集群的模板，而不是集群本身。您仍然可以通过编辑您的集群来更改任何选项：

```
$ kops edit cluster my-rest-cluster.k8s.local

```

这将启动你在 shell 中定义的默认编辑器，在那里你可以看到已生成的集群模板。它将包含更多的设置，不仅仅是你在运行`cluster create`命令时指定的那些：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00123.jpg)

如果你对你的集群模板满意，现在是时候启动它，创建真正的基于云的资源，比如网络和 EC2 实例。一旦基础设施准备好，`kops`将在 EC2 实例上安装 Kubernetes。让我们开始吧。

# 启动集群

要启动集群并启动所有必要的 EC2 实例，你需要执行`update`命令。`kops`手册建议你首先在预览模式下执行，不要使用`--yes`开关。这不会启动任何 EC2 实例：

```
$ kops update cluster ${NAME} 

```

如果一切看起来正确，使用`--yes`开关执行更新命令：

```
$ kops update cluster ${NAME} --yes

```

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00124.jpg)

你的集群正在启动，应该在几分钟内准备就绪。如果你现在登录到 WAS 管理控制台，你会看到你的 EC2 实例正在启动，就像你在下面的截图中看到的那样：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00125.jpg)

你也可以通过发出以下命令来检查整个集群状态：

```
$ kops validate cluster

```

输出将包含有关集群节点数量和状态的信息，包括主节点：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00126.jpg)

当然，由于`kubectl`现在配置为在我们的 AWS 集群上操作，我们可以使用`kubectl get nodes`命令列出节点，就像我们在第九章中使用`minikube`基础集群一样。执行以下命令：

```
$ list nodes: kubectl get nodes --show-labels

```

将会给你提供有关你的集群节点名称和状态的信息：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00127.jpg)

# 更新集群

`Kops`的行为类似于`kubectl`；你可以在编辑器中编辑配置文件，然后再实际对集群进行任何更改。`kops update`命令将应用配置更改，但不会修改正在运行的基础设施。要更新运行中的集群，你需要执行`rolling-update`命令。以下将启动集群基础设施的更新或重建过程：

```
 $ kops 

rolling

-

update 

cluster

 –

yes 

```

我们的新集群正在运行，但是它是空的。让我们部署一些东西。

# 安装仪表板

当集群运行时，部署一个仪表板会很好，以查看您的服务、部署、Pod 等的状态。仪表板默认包含在 `minikube` 集群中，但是在我们全新的亚马逊集群上，我们需要手动安装它。这是一个简单的过程。由于我们已经配置了 `kubectl` 来操作远程集群，我们可以使用 `kubernetes-dashboard.yaml` 模板作为输入执行以下 `kubectl create` 命令：

```
$ kubectl create -f \

https://rawgit.com/kubernetes/dashboard/master/src/deploy

kubernetes-dashboard.yaml

```

接下来要做的事情是代理网络流量，使用我们已经知道的以下 `kubectl proxy` 命令：

```
$ kubectl proxy

```

就是这样！过一会儿，仪表板将被部署，我们将能够使用本地主机地址访问它：

`http://localhost:8001/`，如下截图所示，是我们在第九章中已经看到的相同的仪表板，*使用 Kubernetes API*：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00128.jpg)

从现在开始，您可以使用 `kubectl` 和仪表板来管理您的集群，就像我们在第九章中所做的那样，*使用 Kubernetes API*。所有 `kubectl create` 命令将与本地集群一样工作。但是，这一次，您的软件将部署到云端。

如果您决定删除集群，请执行以下命令：

```
$ kops delete cluster -name=${NAME} --yes

```

请注意，如果您只是创建了集群模板，而没有首先执行 `kops update cluster ${NAME} --yes`，您也可以删除集群，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00129.jpg)

如果集群已经在亚马逊上创建，删除过程将需要更长时间，因为首先需要关闭所有主节点和工作节点的 EC2 实例。

# 摘要

在本章中，我们在真正的云端，亚马逊 AWS 上设置了一个集群。`Kops`是我们目前可用的最好的工具之一，用于在 AWS 上管理 Kubernetes。使用它，您可以轻松地在 AWS 上创建和管理集群。它可以是一个测试或生产级别的集群；`kops`将使其创建和管理变得轻而易举。
