# Kubernetes 开发指南（一）

> 原文：[`zh.annas-archive.org/md5/DCD16B633B67524B76A687C2FBCAAD70`](https://zh.annas-archive.org/md5/DCD16B633B67524B76A687C2FBCAAD70)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

发现自己不仅负责编写代码，还负责运行代码的责任越来越普遍。虽然许多公司仍然有一个运维组（通常更名为 SRE 或 DevOps），他们可以提供专业知识，但开发人员（就像你）经常被要求扩展自己的知识和责任范围。

将基础设施视为代码已经有一段时间了。几年前，我可能会描述边界为 Puppet 由运维人员使用，而 Chef 由开发人员使用。随着云的出现和发展，以及最近 Docker 的发展，所有这些都发生了变化。容器提供了一定程度的控制和隔离，以及非常吸引人的开发灵活性。当使用容器时，您很快就会发现自己想要一次使用多个容器，以实现责任的隔离和水平扩展。

Kubernetes 是一个由 Google 开源的项目，现在由云原生计算基金会托管。它展示了 Google 在容器中运行软件的经验，并使其对您可用。它不仅包括运行容器，还将它们组合成服务，水平扩展它们，以及提供控制这些容器如何相互交互以及如何向外界暴露的手段。

Kubernetes 提供了一个由 API 和命令行工具支持的声明性结构。Kubernetes 可以在您的笔记本电脑上使用，也可以从众多云提供商中利用。使用 Kubernetes 的好处是能够使用相同的一套工具和相同的期望，无论是在本地运行，还是在您公司的小型实验室，或者在任何数量的较大云提供商中运行。这并不完全是 Java 从过去的日子里承诺的一次编写，随处运行；更多的是，我们将为您提供一致的一套工具，无论是在您的笔记本电脑上运行，还是在您公司的数据中心，或者在 AWS、Azure 或 Google 等云提供商上运行。

这本书是您利用 Kubernetes 及其功能开发、验证和运行代码的指南。

这本书侧重于示例和样本，带您了解如何使用 Kubernetes 并将其整合到您的开发工作流程中。通过这些示例，我们关注您可能想要利用 Kubernetes 运行代码的常见任务。

# 这本书是为谁准备的

如果您是一名全栈或后端软件开发人员，对测试和运行您正在开发的代码感兴趣、好奇或被要求负责，您可以利用 Kubernetes 使该过程更简单和一致。如果您正在寻找 Node.js 和 Python 中面向开发人员的示例，以了解如何使用 Kubernetes 构建、测试、部署和运行代码，那么本书非常适合您。

# 本书涵盖内容

第一章《为开发设置 Kubernetes》涵盖了 kubectl、minikube 和 Docker 的安装，以及使用 minikube 运行 kubectl 来验证您的安装。本章还介绍了 Kubernetes 中节点、Pod、容器、ReplicaSets 和部署的概念。

第二章《在 Kubernetes 中打包您的代码》解释了如何将您的代码打包到容器中，以便在 Python 和 Node.js 中使用 Kubernetes 进行示例。

第三章《与 Kubernetes 中的代码交互》涵盖了如何在 Kubernetes 中运行容器，如何访问这些容器，并介绍了 Kubernetes 的 Services、Labels 和 Selectors 概念。

第四章《声明性基础设施》介绍了如何以声明性结构表达您的应用程序，以及如何扩展以利用 Kubernetes 的 ConfigMaps、Annotations 和 Secrets 概念。

第五章《Pod 和容器生命周期》探讨了 Kubernetes 中容器和 Pod 的生命周期，以及如何公开来自您的应用程序的钩子以影响 Kubernetes 运行您的代码，以及如何优雅地终止您的代码。

第六章《Kubernetes 中的后台处理》解释了 Kubernetes 中作业和 CronJob 的批处理概念，并介绍了 Kubernetes 如何处理持久性，包括持久卷、持久卷索赔和有状态集。

第七章《监控和指标》涵盖了 Kubernetes 中的监控，以及如何利用 Prometheus 和 Grafana 捕获和显示有关 Kubernetes 和您的应用程序的指标和简单仪表板。

第八章，*日志和跟踪*，解释了如何使用 ElasticSearch、FluentD 和 Kibana 在 Kubernetes 中收集日志，以及如何设置和使用 Jaeger 进行分布式跟踪。

第九章，*集成测试*，介绍了利用 Kubernetes 的测试策略，以及如何在集成和端到端测试中利用 Kubernetes。

第十章，*故障排除常见问题和下一步*，回顾了您在开始使用 Kubernetes 时可能遇到的一些常见痛点，并解释了如何解决这些问题，并概述了 Kubernetes 生态系统中一些可能对开发人员和开发流程感兴趣的项目。

# 为了充分利用本书

您需要满足以下软件和硬件要求：

+   Kubernetes 1.8

+   Docker 社区版

+   kubectl 1.8（Kubernetes 的一部分）

+   VirtualBox v5.2.6 或更高版本

+   minikube v0.24.1

+   MacBook 或 Linux 机器，内存为 4GB 或更多

# 下载示例代码文件

您可以从您在[www.packtpub.com](http://www.packtpub.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了本书，您可以访问[www.packtpub.com/support](http://www.packtpub.com/support)并注册，以便文件直接发送到您的邮箱。

您可以按照以下步骤下载代码文件：

1.  登录或注册[www.packtpub.com](http://www.packtpub.com/support)。

1.  选择“支持”选项卡。

1.  单击“代码下载和勘误”。

1.  在搜索框中输入书名，然后按照屏幕上的说明操作。

下载文件后，请确保使用以下最新版本解压或提取文件夹：

+   Windows 上的 WinRAR/7-Zip

+   Mac 上的 Zipeg/iZip/UnRarX

+   Linux 上的 7-Zip/PeaZip

该书的代码包也托管在 GitHub 上，网址如下：

+   [`github.com/kubernetes-for-developers/kfd-nodejs`](https://github.com/kubernetes-for-developers/kfd-nodejs)

+   [`github.com/kubernetes-for-developers/kfd-flask`](https://github.com/kubernetes-for-developers/kfd-flask)

+   [`github.com/kubernetes-for-developers/kfd-celery`](https://github.com/kubernetes-for-developers/kfd-celery)

如果代码有更新，将在现有的 GitHub 存储库中进行更新。

我们还有其他代码包来自我们丰富的书籍和视频目录，可在**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)**上找到。去看看吧！

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。例如：“将下载的`WebStorm-10*.dmg`磁盘映像文件挂载为系统中的另一个磁盘。”

代码块设置如下：

```
import signal
import sys
def sigterm_handler(_signo, _stack_frame):
sys.exit(0)
signal.signal(signal.SIGTERM, sigterm_handler) 

```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目会以粗体显示：

```
import signal
**import sys**
def sigterm_handler(_signo, _stack_frame):
sys.exit(0)
signal.signal(signal.SIGTERM, sigterm_handler) 
```

任何命令行输入或输出都是这样写的：

```
 kubectl apply -f simplejob.yaml 
```

**粗体**：表示新术语、重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词会以这种方式出现在文本中。例如：“从管理面板中选择系统信息。”

警告或重要说明会显示为这样。提示和技巧显示为这样。


# 第一章：为开发设置 Kubernetes

欢迎来到*面向开发人员的 Kubernetes*！本章首先将帮助您安装工具，以便您可以在开发中充分利用 Kubernetes。安装完成后，我们将与这些工具进行一些交互，以验证它们是否正常工作。然后，我们将回顾一些您作为开发人员想要了解的基本概念，以有效地使用 Kubernetes。我们将介绍 Kubernetes 中的以下关键资源：

+   容器

+   Pod

+   节点

+   部署

+   副本集

# 开发所需的工具

除了您通常使用的编辑和编程工具之外，您还需要安装软件来利用 Kubernetes。本书的重点是让您可以在本地开发机器上完成所有操作，同时也可以在将来如果需要更多资源，扩展和利用远程 Kubernetes 集群。Kubernetes 的一个好处是它以相同的方式处理一个或一百台计算机，让您可以利用您软件所需的资源，并且无论它们位于何处，都可以一致地进行操作。

本书中的示例将使用本地机器上终端中的命令行工具。主要的工具将是`kubectl`，它与 Kubernetes 集群通信。我们将使用 Minikube 在您自己的开发系统上运行的单台机器的微型 Kubernetes 集群。我建议安装 Docker 的社区版，这样可以轻松地构建用于 Kubernetes 内部的容器：

+   `kubectl`：`kubectl`（如何发音是 Kubernetes 社区内一个有趣的话题）是用于与 Kubernetes 集群一起工作的主要命令行工具。要安装`kubectl`，请访问页面[`kubernetes.io/docs/tasks/tools/install-kubectl/`](https://kubernetes.io/docs/tasks/tools/install-kubectl/)并按照适用于您平台的说明进行操作。

+   `minikube`：要安装 Minikube，请访问页面[`github.com/kubernetes/minikube/releases`](https://github.com/kubernetes/minikube/releases)并按照适用于您平台的说明进行操作。

+   `docker`：要安装 Docker 的社区版，请访问网页[`www.docker.com/community-edition`](https://www.docker.com/community-edition)并按照适用于您平台的说明进行操作。

# 可选工具

除了`kubectl`、`minikube`和`docker`之外，您可能还想利用其他有用的库和命令行工具。

`jq`是一个命令行 JSON 处理器，它可以轻松解析更复杂的数据结构中的结果。我会将其描述为*更擅长处理 JSON 结果的 grep 表亲*。您可以按照[`stedolan.github.io/jq/download/`](https://stedolan.github.io/jq/download/)上的说明安装`jq`。关于`jq`的详细信息以及如何使用它也可以在[`stedolan.github.io/jq/manual/`](https://stedolan.github.io/jq/manual/)上找到。

# 启动本地集群

一旦 Minikube 和 Kubectl 安装完成，就可以启动一个集群。值得知道你正在使用的工具的版本，因为 Kubernetes 是一个发展迅速的项目，如果需要从社区获得帮助，知道这些常用工具的版本将很重要。

我在撰写本文时使用的 Minikube 和`kubectl`的版本是：

+   Minikube：版本 0.22.3

+   `kubectl`：版本 1.8.0

您可以使用以下命令检查您的副本的版本：

```
minikube version
```

这将输出一个版本：

```
minikube version: v0.22.3
```

如果在按照安装说明操作时还没有这样做，请使用 Minikube 启动 Kubernetes。最简单的方法是使用以下命令：

```
minikube start
```

这将下载一个虚拟机映像并启动它，以及在其上的 Kubernetes，作为单机集群。输出将类似于以下内容：

```
Downloading Minikube ISO
 106.36 MB / 106.36 MB [============================================] 100.00% 0s
Getting VM IP address...
Moving files into cluster...
Setting up certs...
Connecting to cluster...
Setting up kubeconfig...
Starting cluster components...
Kubectl is now configured to use the cluster.
```

Minikube 将自动创建`kubectl`访问集群和控制集群所需的文件。完成后，可以获取有关集群的信息以验证其是否正在运行。

首先，您可以直接询问`minikube`关于其状态：

```
minikube status
minikube: Running
cluster: Running
kubectl: Correctly Configured: pointing to minikube-vm at 192.168.64.2
```

如果我们询问`kubectl`关于其版本，它将报告客户端的版本和正在通信的集群的版本：

```
kubectl version
```

第一个输出是`kubectl`客户端的版本：

```
Client Version: version.Info{Major:"1", Minor:"7", GitVersion:"v1.7.5", GitCommit:"17d7182a7ccbb167074be7a87f0a68bd00d58d97", GitTreeState:"clean", BuildDate:"2017-08-31T19:32:26Z", GoVersion:"go1.9", Compiler:"gc", Platform:"darwin/amd64"}
```

立即之后，它将通信并报告集群上 Kubernetes 的版本：

```
Server Version: version.Info{Major:"1", Minor:"7", GitVersion:"v1.7.5", GitCommit:"17d7182a7ccbb167074be7a87f0a68bd00d58d97", GitTreeState:"clean", BuildDate:"2017-09-11T21:52:19Z", GoVersion:"go1.8.3", Compiler:"gc", Platform:"linux/amd64"}
```

我们也可以使用`kubectl`来请求有关集群的信息：

```
kubectl cluster-info
```

然后会看到类似以下的内容：

```
Kubernetes master is running at https://192.168.64.2:8443

To further debug and diagnose cluster problems, use 'kubectl cluster-info dump'.
```

此命令主要让您知道您正在通信的 API 服务器是否正在运行。我们可以使用附加命令来请求关键内部组件的特定状态：

```
kubectl get componentstatuses
```

```
NAME                 STATUS    MESSAGE              ERROR
scheduler            Healthy   ok
etcd-0               Healthy   {"health": "true"}
controller-manager   Healthy   ok
```

Kubernetes 还报告并存储了许多事件，您可以请求查看这些事件。这些显示了集群内部发生的情况：

```
kubectl get events
```

```
LASTSEEN   FIRSTSEEN   COUNT     NAME       KIND      SUBOBJECT   TYPE      REASON                    SOURCE                 MESSAGE
2m         2m          1         minikube   Node                  Normal    Starting                  kubelet, minikube      Starting kubelet.
2m         2m          2         minikube   Node                  Normal    NodeHasSufficientDisk     kubelet, minikube      Node minikube status is now: NodeHasSufficientDisk
2m         2m          2         minikube   Node                  Normal    NodeHasSufficientMemory   kubelet, minikube      Node minikube status is now: NodeHasSufficientMemory
2m         2m          2         minikube   Node                  Normal    NodeHasNoDiskPressure     kubelet, minikube      Node minikube status is now: NodeHasNoDiskPressure
2m         2m          1         minikube   Node                  Normal    NodeAllocatableEnforced   kubelet, minikube      Updated Node Allocatable limit across pods
2m         2m          1         minikube   Node                  Normal    Starting                  kube-proxy, minikube   Starting kube-proxy.
2m         2m          1         minikube   Node                  Normal    RegisteredNode            controllermanager      Node minikube event: Registered Node minikube in NodeController
```

# 重置和重新启动您的集群

如果您想清除本地 Minikube 集群并重新启动，这是非常容易做到的。发出一个`delete`命令，然后`start` Minikube 将清除环境并将其重置为一个空白状态：

```
minikube delete Deleting local Kubernetes cluster...
Machine deleted.

minikube start
Starting local Kubernetes v1.7.5 cluster...
Starting VM...
Getting VM IP address...
Moving files into cluster...
Setting up certs...
Connecting to cluster...
Setting up kubeconfig...
Starting cluster components...
Kubectl is now configured to use the cluster.
```

# 查看 Minikube 内置和包含的内容

使用 Minikube，您可以通过一个命令为 Kubernetes 集群启动基于 Web 的仪表板：

```
minikube dashboard
```

这将打开一个浏览器，并显示一个 Kubernetes 集群的 Web 界面。如果您查看浏览器窗口中的 URL 地址，您会发现它指向之前从`kubectl cluster-info`命令返回的相同 IP 地址，运行在端口`30000`上。仪表板在 Kubernetes 内部运行，并且它不是唯一的运行在其中的东西。

Kubernetes 是自托管的，支持 Kubernetes 运行的支持组件，如仪表板、DNS 等，都在 Kubernetes 内部运行。您可以通过查询集群中所有 Pod 的状态来查看所有这些组件的状态：

```
kubectl get pods --all-namespaces
```

```
NAMESPACE     NAME                          READY     STATUS    RESTARTS   AGE
kube-system   kube-addon-manager-minikube   1/1       Running   0          6m
kube-system   kube-dns-910330662-6pctd      3/3       Running   0          6m
kube-system   kubernetes-dashboard-91nmv    1/1       Running   0          6m
```

请注意，在此命令中我们使用了`--all-namespaces`选项。默认情况下，`kubectl`只会显示位于默认命名空间中的 Kubernetes 资源。由于我们还没有运行任何东西，如果我们调用`kubectl get pods`，我们将只会得到一个空列表。Pod 并不是唯一的 Kubernetes 资源；您可以查询许多不同的资源，其中一些我将在本章后面描述，更多的将在后续章节中描述。

暂时，再调用一个命令来获取服务列表：

```
kubectl get services --all-namespaces
```

这将输出所有服务：

```
NAMESPACE     NAME                   CLUSTER-IP   EXTERNAL-IP   PORT(S)         AGE
default       kubernetes             10.0.0.1     <none>        443/TCP         3m
kube-system   kube-dns               10.0.0.10    <none>        53/UDP,53/TCP   2m
kube-system   kubernetes-dashboard   10.0.0.147   <nodes>       80:30000/TCP    2m
```

请注意名为`kubernetes-dashboard`的服务具有`Cluster-IP`值和端口`80:30000`。该端口配置表明，在支持`kubernetes-dashboard`服务的 Pod 中，它将把来自端口`30000`的任何请求转发到容器内的端口`80`。您可能已经注意到，Cluster IP 的 IP 地址与我们之前在`kubectl cluster-info`命令中看到的 Kubernetes 主节点报告的 IP 地址非常不同。

重要的是要知道，Kubernetes 中的所有内容都在一个私有的、隔离的网络上运行，通常无法从集群外部访问。我们将在未来的章节中更详细地介绍这一点。现在，只需知道`minikube`在其中有一些额外的特殊配置来暴露仪表板。

# 验证 Docker

Kubernetes 支持多种运行容器的方式，Docker 是最常见、最方便的方式。在本书中，我们将使用 Docker 来帮助我们创建在 Kubernetes 中运行的镜像。

您可以通过运行以下命令来查看您安装的 Docker 版本并验证其是否可操作：

```
docker  version
```

像`kubectl`一样，它将报告`docker`客户端版本以及服务器版本，您的输出可能看起来像以下内容：

```
Client:
 Version: 17.09.0-ce
 API version: 1.32
 Go version: go1.8.3
 Git commit: afdb6d4
 Built: Tue Sep 26 22:40:09 2017
 OS/Arch: darwin/amd64
```

```
Server:
 Version: 17.09.0-ce
 API version: 1.32 (minimum version 1.12)
 Go version: go1.8.3
 Git commit: afdb6d4
 Built: Tue Sep 26 22:45:38 2017
 OS/Arch: linux/amd64
 Experimental: false
```

通过使用`docker images`命令，您可以查看本地可用的容器镜像，并使用`docker pull`命令，您可以请求特定的镜像。在下一章的示例中，我们将基于 alpine 容器镜像构建我们的软件，因此让我们继续拉取该镜像以验证您的环境是否正常工作：

```
docker pull alpine 
Using default tag: latest
latest: Pulling from library/alpine
Digest: sha256:f006ecbb824d87947d0b51ab8488634bf69fe4094959d935c0c103f4820a417d
Status: Image is up to date for alpine:latest
```

然后，您可以使用以下命令查看镜像：

```
docker images
```

```
REPOSITORY TAG IMAGE ID CREATED SIZE
alpine latest 76da55c8019d 3 weeks ago 3.97MB</strong>
```

如果在尝试拉取 alpine 镜像时出现错误，这可能意味着您需要通过代理工作，或者以其他方式受限制地访问互联网以满足您的镜像需求。如果您处于这种情况，您可能需要查看 Docker 关于如何设置和使用代理的信息。

# 清除和清理 Docker 镜像

由于我们将使用 Docker 来构建容器镜像，了解如何摆脱镜像将是有用的。您已经使用`docker image`命令看到了镜像列表。还有一些由 Docker 维护的中间镜像在输出中是隐藏的。要查看 Docker 存储的所有镜像，请使用以下命令：

```
docker images -a
```

如果您只按照前文拉取了 alpine 镜像，可能不会看到任何其他镜像，但在下一章中构建镜像时，这个列表将会增长。

您可以使用`docker rmi`命令后跟镜像的名称来删除镜像。默认情况下，Docker 将尝试维护容器最近使用或引用的镜像。因此，您可能需要强制删除以清理镜像。

如果您想重置并删除所有镜像并重新开始，有一个方便的命令可以做到。通过结合 Docker 镜像和`docker rmi`，我们可以要求它强制删除所有已知的镜像：

```
docker rmi -f $(docker images -a -q)
```

# Kubernetes 概念 - 容器

Kubernetes（以及这个领域中的其他技术）都是关于管理和编排容器的。容器实际上是一个包裹了一系列 Linux 技术的名称，其中最突出的是容器镜像格式和 Linux 如何隔离进程，利用 cgroups。

在实际情况下，当有人谈论容器时，他们通常意味着有一个包含运行单个进程所需的一切的镜像。在这种情况下，容器不仅是镜像，还包括关于如何调用和运行它的信息。容器还表现得好像它们有自己的网络访问权限。实际上，这是由运行容器的 Linux 操作系统共享的。

当我们想要编写在 Kubernetes 下运行的代码时，我们总是在谈论将其打包并准备在容器内运行。本书后面更复杂的示例将利用多个容器一起工作。

在容器内运行多个进程是完全可能的，但这通常被视为不好的做法，因为容器理想上适合表示单个进程以及如何调用它，并且不应被视为完整虚拟机的同一物体。

如果你通常使用 Python 进行开发，那么你可能熟悉使用类似`pip`的工具来下载你需要的库和模块，并使用类似`python your_file`的命令来调用你的程序。如果你是 Node 开发人员，那么你更可能熟悉使用`npm`或`yarn`来安装你需要的依赖，并使用`node your_file`来运行你的代码。

如果你想把所有这些打包起来，在另一台机器上运行，你可能要重新执行所有下载库和运行代码的指令，或者可能将整个目录压缩成 ZIP 文件，然后将其移动到想要运行的地方。容器是一种将所有信息收集到单个镜像中的方式，以便可以轻松地移动、安装和在 Linux 操作系统上运行。最初由 Docker 创建，现在由**Open Container Initiative**（**OCI**）（[`www.opencontainers.org`](https://www.opencontainers.org)）维护规范。

虽然容器是 Kubernetes 中的最小构建块，但 Kubernetes 处理的最小单位是 Pod。

# Kubernetes 资源 - Pod

Pod 是 Kubernetes 管理的最小单位，也是系统其余部分构建在其上的基本单位。创建 Kubernetes 的团队发现让开发人员指定应始终在同一操作系统上运行的进程，并且应该一起运行的进程组合应该是被调度、运行和管理的单位是值得的。

在本章的前面，您看到 Kubernetes 的一个基本实例有一些软件在 Pod 中运行。Kubernetes 的许多部分都是使用这些相同的概念和抽象来运行的，这使得 Kubernetes 能够自托管其自己的软件。一些用于运行 Kubernetes 集群的软件是在集群之外管理的，但越来越多地利用了 Pod 的概念，包括 DNS 服务、仪表板和控制器管理器，它们通过 Kubernetes 协调所有的控制操作。

一个 Pod 由一个或多个容器以及与这些容器相关的信息组成。当您询问 Kubernetes 有关一个 Pod 时，它将返回一个数据结构，其中包括一个或多个容器的列表，以及 Kubernetes 用来协调 Pod 与其他 Pod 以及 Kubernetes 应该如何在程序失败时采取行动的各种元数据。元数据还可以定义诸如*亲和性*之类的东西，影响 Pod 在集群中可以被调度的位置，以及如何获取容器镜像等期望。重要的是要知道，Pod 不打算被视为持久的、长期存在的实体。

它们被创建和销毁，本质上是短暂的。这允许单独的逻辑 - 包含在控制器中 - 来管理规模和可用性等责任。正是这种分工的分离使得 Kubernetes 能够在发生故障时提供自我修复的手段，并提供一些自动扩展的能力。

由 Kubernetes 运行的 Pod 具有一些特定的保证：

+   一个 Pod 中的所有容器将在同一节点上运行。

+   在 Pod 中运行的任何容器都将与同一 Pod 中的其他容器共享节点的网络

+   Pod 中的容器可以通过挂载到容器的卷共享文件。

+   一个 Pod 有一个明确的生命周期，并且始终保留在它启动的节点上。

在实际操作中，当您想要了解 Kubernetes 集群上运行的内容时，通常会想要了解 Kubernetes 中运行的 Pod 及其状态。

Kubernetes 维护并报告 Pod 的状态，以及组成 Pod 的每个容器的状态。容器的状态包括`Running`、`Terminated`和`Waiting`。Pod 的生命周期稍微复杂一些，包括严格定义的阶段和一组 PodStatus。阶段包括`Pending`、`Running`、`Succeeded`、`Failed`或`Unknown`，阶段中包含的具体细节在[`kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle/#pod-phase`](https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle/#pod-phase)中有文档记录。

Pod 还可以包含探针，用于主动检查容器的某些状态信息。Kubernetes 控制器部署和使用的两个常见探针是`livenessProbe`和`readinessProbe`。`livenessProbe`定义容器是否正在运行。如果没有运行，Kubernetes 基础设施会终止相关容器，然后应用为 Pod 定义的重启策略。`readinessProbe`用于指示容器是否准备好提供服务请求。`readinessProbe`的结果与其他 Kubernetes 机制（稍后我们将详细介绍）一起使用，以将流量转发到相关容器。通常，探针被设置为允许容器中的软件向 Kubernetes 提供反馈循环。您可以在[`kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle/#container-probes`](https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle/#container-probes)找到有关探针的更多详细信息，如何定义它们以及它们的用途。我们将在未来的章节中详细讨论探针。

# 命名空间

Pod 被收集到命名空间中，用于将 Pod 组合在一起以实现各种目的。在之前使用`--all-namespaces`选项请求集群中所有 Pod 的状态时，您已经看到了命名空间的一个示例。

命名空间可用于提供资源使用配额和限制，对 Kubernetes 在集群内部创建的 DNS 名称产生影响，并且在将来可能会影响访问控制策略。如果在通过`kubectl`与 Kubernetes 交互时未指定命名空间，则命令会假定您正在使用名为`default`的默认命名空间。

# 编写您的 Pods 和容器的代码

成功使用 Kubernetes 的关键之一是考虑您希望代码如何运行，并将其结构化，使其清晰地适应 Pod 和容器的结构。通过将软件解决方案结构化为将问题分解为符合 Kubernetes 提供的约束和保证的组件，您可以轻松地利用并行性和容器编排，以像使用单台机器一样无缝地使用多台机器。

Kubernetes 提供的保证和抽象反映了 Google（和其他公司）在以大规模、可靠和冗余的方式运行其软件和服务方面多年的经验，利用水平扩展的模式来解决重大问题。

# Kubernetes 资源-节点

节点是一台机器，通常运行 Linux，已添加到 Kubernetes 集群中。它可以是物理机器或虚拟机。在`minikube`的情况下，它是一台运行 Kubernetes 所有软件的单个虚拟机。在较大的 Kubernetes 集群中，您可能有一台或多台专门用于管理集群的机器，以及单独的机器用于运行工作负载。Kubernetes 通过跟踪节点的资源使用情况、调度、启动（如果需要，重新启动）Pod，以及协调连接 Pod 或在集群外部公开它们的其他机制来管理其资源。

节点可以（而且确实）与它们关联的元数据，以便 Kubernetes 可以意识到相关的差异，并在调度和运行 Pod 时考虑这些差异。Kubernetes 可以支持各种各样的机器共同工作，并在所有这些机器上高效运行软件，或者将 Pod 的调度限制在只有所需资源的机器上（例如，GPU）。

# 网络

我们之前提到，Pod 中的所有容器共享节点的网络。此外，Kubernetes 集群中的所有节点都应该相互连接并共享一个私有的集群范围网络。当 Kubernetes 在 Pod 中运行容器时，它是在这个隔离的网络中进行的。Kubernetes 负责处理 IP 地址，创建 DNS 条目，并确保一个 Pod 可以与同一 Kubernetes 集群中的另一个 Pod 进行通信。

另一个资源是服务，我们稍后会深入研究，这是 Kubernetes 用来在私有网络中向其他 Pod 公开或处理集群内外的连接的工具。默认情况下，在这个私有的隔离网络中运行的 Pod 不会暴露在 Kubernetes 集群之外。根据您的 Kubernetes 集群是如何创建的，有多种方式可以打开从集群外部访问您的软件的途径，我们将在稍后的服务中详细介绍，包括负载均衡器、节点端口和入口。

# 控制器

Kubernetes 的构建理念是告诉它你想要什么，它知道如何去做。当您与 Kubernetes 交互时，您断言您希望一个或多个资源处于特定状态，具有特定版本等等。控制器是跟踪这些资源并尝试按照您描述的方式运行软件的大脑所在的地方。这些描述可以包括运行容器镜像的副本数量、更新 Pod 中运行的软件版本，以及处理节点故障的情况，其中您意外地失去了集群的一部分。

Kubernetes 中使用了各种控制器，它们大多隐藏在我们将进一步深入研究的两个关键资源后面：部署和 ReplicaSets。

# Kubernetes 资源 – ReplicaSet

ReplicaSet 包装了 Pod，定义了需要并行运行多少个 Pod。ReplicaSet 通常又被部署包装。ReplicaSets 不经常直接使用，但对于表示水平扩展来说至关重要——表示要运行的并行 Pod 的数量。

ReplicaSet 与 Pod 相关联，并指示集群中应该运行多少个该 Pod 的实例。ReplicaSet 还意味着 Kubernetes 有一个控制器来监视持续状态，并知道要保持运行多少个 Pod。这就是 Kubernetes 真正开始为您工作的地方，如果您在 ReplicaSet 中指定了三个 Pod，而其中一个失败了，Kubernetes 将自动为您安排并运行另一个 Pod。

# Kubernetes 资源 – 部署

在 Kubernetes 上运行代码的最常见和推荐方式是使用部署，由部署控制器管理。我们将在接下来的章节中探讨部署，直接指定它们并使用诸如 `kubectl run` 等命令隐式创建它们。

Pod 本身很有趣，但受限，特别是因为它旨在是短暂的。如果一个节点死掉（或者被关机），那个节点上的所有 Pod 都将停止运行。ReplicaSets 提供了自我修复的能力。它们在集群内工作，以识别 Pod 何时不再可用，并尝试调度另一个 Pod，通常是为了使服务恢复在线，或者继续工作。

部署控制器包装并扩展了 ReplicaSet 控制器，主要负责推出软件更新并管理更新部署资源的过程。部署控制器包括元数据设置，以了解要保持运行多少个 Pod，以便通过添加容器的新版本来启用无缝滚动更新软件，并在您请求时停止旧版本。

# 代表 Kubernetes 资源

Kubernetes 资源通常可以表示为 JSON 或 YAML 数据结构。Kubernetes 专门设计成可以保存这些文件，当您想要运行软件时，可以使用诸如`kubectl deploy`之类的命令，并提供先前创建的定义，然后使用它来运行您的软件。在我们的下一章中，我们将开始展示这些资源的具体示例，并为我们的使用构建它们。

当我们进入下一个和未来的章节中的示例时，我们将使用 YAML 来描述我们的资源，并通过`kubectl`以 JSON 格式请求数据。所有这些数据结构都是针对 Kubernetes 的每个版本进行正式定义的，以及 Kubernetes 提供的用于操作它们的 REST API。所有 Kubernetes 资源的正式定义都在源代码控制中使用 OpenAPI（也称为**Swagger**）进行维护，并可以在[`github.com/kubernetes/kubernetes/tree/master/api/swagger-spec`](https://github.com/kubernetes/kubernetes/tree/master/api/swagger-spec)上查看。

# 总结

在本章中，我们安装了`minikube`和`kubectl`，并使用它们启动了一个本地 Kubernetes 集群，并简要地与之交互。然后，我们简要介绍了一些关键概念，我们将在未来的章节中更深入地使用和探索，包括容器、Pod、节点、部署和 ReplicaSet。

在下一章中，我们将深入探讨将软件放入容器所需的步骤，以及如何在自己的项目中设置容器的技巧。我们将以 Python 和 Node.js 为例，演示如何将软件放入容器，你可以将其作为自己代码的起点。


# 第二章：将您的代码打包以在 Kubernetes 中运行

在本章中，我们将深入探讨使用 Kubernetes 所需的第一件事：将软件放入容器中。我们将回顾容器是什么，如何存储和共享镜像，以及如何构建容器。然后，本章继续进行两个示例，一个是 Python，另一个是 Node.js，它们将引导您如何将这些语言的简单示例代码构建成容器，并在 Kubernetes 中运行它们。本章的部分内容包括：

+   容器镜像

+   制作自己的容器

+   Python 示例-制作容器镜像

+   Node.js 示例-制作容器镜像

+   给您的容器镜像打标签

# 容器镜像

使用 Kubernetes 的第一步是将您的软件放入容器中。Docker 是创建这些容器的最简单方法，而且这是一个相当简单的过程。让我们花点时间来查看现有的容器镜像，以了解在创建自己的容器时需要做出什么选择：

```
docker pull docker.io/jocatalin/kubernetes-bootcamp:v1
```

首先，您将看到它下载具有奥秘 ID 的文件列表。您会看到它们并行更新，因为它尝试在可用时抓取它们：

```
v1: Pulling from jocatalin/kubernetes-bootcamp
5c90d4a2d1a8: Downloading  3.145MB/51.35MB
ab30c63719b1: Downloading  3.931MB/18.55MB
29d0bc1e8c52: Download complete
d4fe0dc68927: Downloading  2.896MB/13.67MB
dfa9e924f957: Waiting
```

当下载完成时，输出将更新为“提取”，最后为“拉取完成”：

```
v1: Pulling from jocatalin/kubernetes-bootcamp
5c90d4a2d1a8: Pull complete
ab30c63719b1: Pull complete
29d0bc1e8c52: Pull complete
d4fe0dc68927: Pull complete
dfa9e924f957: Pull complete
Digest: sha256:0d6b8ee63bb57c5f5b6156f446b3bc3b3c143d233037f3a2f00e279c8fcc64af
Status: Downloaded newer image for jocatalin/kubernetes-bootcamp:v1
```

您在终端中看到的是 Docker 正在下载构成容器镜像的层，将它们全部汇集在一起，然后验证输出。当您要求 Kubernetes 运行软件时，Kubernetes 正是执行这个相同的过程，下载镜像然后运行它们。

如果您现在运行以下命令：

```
docker images
```

您将看到（也许还有其他）列出的镜像类似于这样：

```
REPOSITORY                                         TAG                 IMAGE ID            CREATED             SIZE
jocatalin/kubernetes-bootcamp                      v1                  8fafd8af70e9        13 months ago       211MB
```

该镜像的大小为`211MB`，当我们指定`jocatalin/kubernetes-bootcamp:v1`时，您会注意到我们同时指定了一个名称`jocatalin/kubernetes-bootcamp`和一个标签`v1`。此外，该镜像具有一个`IMAGE ID`（`8fafd8af70e9`），这是整个镜像的唯一 ID。如果您要为镜像指定一个名称而没有标签，那么默认情况下会假定您想要一个默认标签`latest`。

让我们深入了解刚刚下载的镜像，使用`docker history`命令：

```
docker history jocatalin/kubernetes-bootcamp:v1
```

```
IMAGE               CREATED             CREATED BY                                      SIZE                COMMENT
8fafd8af70e9        13 months ago       /bin/sh -c #(nop)  CMD ["/bin/sh" "-c" "no...   0B
<missing>           13 months ago       /bin/sh -c #(nop) COPY file:de8ef36ebbfd53...   742B
<missing>           13 months ago       /bin/sh -c #(nop)  EXPOSE 8080/tcp              0B
<missing>           13 months ago       /bin/sh -c #(nop) CMD ["node"]                  0B
<missing>           13 months ago       /bin/sh -c buildDeps='xz-utils'     && set...   41.5MB
<missing>           13 months ago       /bin/sh -c #(nop) ENV NODE_VERSION=6.3.1        0B
<missing>           15 months ago       /bin/sh -c #(nop) ENV NPM_CONFIG_LOGLEVEL=...   0B
<missing>           15 months ago       /bin/sh -c set -ex   && for key in     955...   80.8kB
<missing>           15 months ago       /bin/sh -c apt-get update && apt-get insta...   44.7MB
<missing>           15 months ago       /bin/sh -c #(nop) CMD ["/bin/bash"]             0B
<missing>           15 months ago       /bin/sh -c #(nop) ADD file:76679eeb94129df...   125MB
```

这明确了我们之前在下载容器时看到的情况：容器镜像由层组成，每一层都建立在它下面的层之上。Docker 镜像的层非常简单——每一层都是执行命令和命令在本地文件系统上所做的任何更改的结果。在之前的`docker history`命令中，您将看到任何更改底层文件系统大小的命令报告的大小。

镜像格式是由 Docker 创建的，现在由**OCI**（**Open Container Initiative**）Image Format 项目正式指定。如果您想进一步了解，可以在[`github.com/opencontainers/image-spec`](https://github.com/opencontainers/image-spec)找到格式和所有相关细节。

容器镜像以及镜像中的每个层通常都可以在互联网上找到。我在本书中使用的所有示例都是公开可用的。可以配置 Kubernetes 集群使用私有镜像仓库，Kubernetes 项目的文档中有关于如何执行该任务的详细说明，网址为[`kubernetes.io/docs/tasks/configure-pod-container/pull-image-private-registry/`](https://kubernetes.io/docs/tasks/configure-pod-container/pull-image-private-registry/)。这种设置更加私密，但设置起来更加复杂，因此在本书中，我们将继续使用公开可用的镜像。

容器镜像还包括如何运行镜像、要运行什么、要设置哪些环境变量等信息。我们可以使用`docker inspect`命令查看所有这些细节：

```
docker inspect jocatalin/kubernetes-bootcamp:v1
```

上述命令生成了相当多的内容，详细描述了容器镜像以及其中运行代码所需的元数据：

```
[
    {
        "Id": "sha256:8fafd8af70e9aa7c3ab40222ca4fd58050cf3e49cb14a4e7c0f460cd4f78e9fe",
        "RepoTags": [
            "jocatalin/kubernetes-bootcamp:v1"
        ],
        "RepoDigests": [
            "jocatalin/kubernetes-bootcamp@sha256:0d6b8ee63bb57c5f5b6156f446b3bc3b3c143d233037f3a2f00e279c8fcc64af"
        ],
        "Parent": "",
        "Comment": "",
        "Created": "2016-08-04T16:46:35.471076443Z",
        "Container": "976a20903b4e8b3d1546e610b3cba8751a5123d76b8f0646f255fe2baf345a41",
        "ContainerConfig": {
            "Hostname": "6250540837a8",
            "Domainname": "",
            "User": "",
            "AttachStdin": false,
            "AttachStdout": false,
            "AttachStderr": false,
            "ExposedPorts": {
                "8080/tcp": {}
            },
            "Tty": false,
            "OpenStdin": false,
            "StdinOnce": false,
            "Env": [
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "NPM_CONFIG_LOGLEVEL=info",
                "NODE_VERSION=6.3.1"
            ],
            "Cmd": [
                "/bin/sh",
                "-c",
                "#(nop) ",
                "CMD [\"/bin/sh\" \"-c\" \"node server.js\"]"
            ],
            "ArgsEscaped": true,
            "Image": "sha256:87ef05c0e8dc9f729b9ff7d5fa6ad43450bdbb72d95c257a6746a1f6ad7922aa",
            "Volumes": null,
            "WorkingDir": "",
            "Entrypoint": null,
            "OnBuild": [],
            "Labels": {}
        },
        "DockerVersion": "1.12.0",
        "Author": "",
        "Architecture": "amd64",
        "Os": "linux",
        "Size": 211336459,
        "VirtualSize": 211336459,

```

除了基本配置之外，Docker 容器镜像还可以包含运行时配置，因此通常会有一个重复的部分，在`ContainerConfig`键下定义了大部分你所说的内容：

```
        "Config": {
            "Hostname": "6250540837a8",
            "Domainname": "",
            "User": "",
            "AttachStdin": false,
            "AttachStdout": false,
            "AttachStderr": false,
            "ExposedPorts": {
                "8080/tcp": {}
            },
            "Tty": false,
            "OpenStdin": false,
            "StdinOnce": false,
            "Env": [
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "NPM_CONFIG_LOGLEVEL=info",
                "NODE_VERSION=6.3.1"
            ],
            "Cmd": [
                "/bin/sh",
                "-c",
                "node server.js"
            ],
            "ArgsEscaped": true,
            "Image": "sha256:87ef05c0e8dc9f729b9ff7d5fa6ad43450bdbb72d95c257a6746a1f6ad7922aa",
            "Volumes": null,
            "WorkingDir": "",
            "Entrypoint": null,
            "OnBuild": [],
            "Labels": {}
        },
```

最后一个部分包括了文件系统的叠加的显式列表以及它们如何组合在一起：

```
"GraphDriver": {
            "Data": {
                "LowerDir": "/var/lib/docker/overlay2/b38e59d31a16f7417c5ec785432ba15b3743df647daed0dc800d8e9c0a55e611/diff:/var/lib/docker/overlay2/792ce98aab6337d38a3ec7d567324f829e73b1b5573bb79349497a9c14f52ce2/diff:/var/lib/docker/overlay2/6c131c8dd754628a0ad2c2aa7de80e58fa6b3f8021f34af684b78538284cf06a/diff:/var/lib/docker/overlay2/160efe1bd137edb08fe180f020054933134395fde3518449ab405af9b1fb6cb0/diff",
                "MergedDir": "/var/lib/docker/overlay2/40746dcac4fe98d9982ce4c0a0f6f0634e43c3b67a4bed07bb97068485cd137a/merged",
                "UpperDir": "/var/lib/docker/overlay2/40746dcac4fe98d9982ce4c0a0f6f0634e43c3b67a4bed07bb97068485cd137a/diff",
                "WorkDir": "/var/lib/docker/overlay2/40746dcac4fe98d9982ce4c0a0f6f0634e43c3b67a4bed07bb97068485cd137a/work"
            },
            "Name": "overlay2"
        },
        "RootFS": {
            "Type": "layers",
            "Layers": [
                "sha256:42755cf4ee95900a105b4e33452e787026ecdefffcc1992f961aa286dc3f7f95",
                "sha256:d1c800db26c75f0aa5881a5965bd6b6abf5101dbb626a4be5cb977cc8464de3b",
                "sha256:4b0bab9ff599d9feb433b045b84aa6b72a43792588b4c23a2e8a5492d7940e9a",
                "sha256:aaed480d540dcb28252b03e40b477e27564423ba0fe66acbd04b2affd43f2889",
                "sha256:4664b95364a615be736bd110406414ec6861f801760dae2149d219ea8209a4d6"
            ]
        }
    }
]
```

JSON 转储中包含了很多信息，可能比你现在需要或关心的要多。最重要的是，我想让你知道它在`config`部分下指定了一个`cmd`，分为三个部分。这是如果你`run`容器时默认会被调用的内容，通常被称为`Entrypoint`。如果你把这些部分组合起来，想象自己在容器中运行它们，你将会运行以下内容：

```
/bin/sh -c node server.js
```

`Entrypoint`定义了将要执行的二进制文件，以及任何参数，并且是指定你想要运行什么以及如何运行的关键。Kubernetes 与这个相同的`Entrypoint`一起工作，并且可以用命令和参数覆盖它，以运行你的软件，或者运行你在同一个容器镜像中存储的诊断工具。

# 容器注册表

在前面的例子中，当我们调用命令来拉取容器时，我们引用了[`www.docker.com/`](https://www.docker.com/)，这是 Docker 的容器注册表。在使用 Kubernetes 或阅读有关 Kubernetes 的文档时，你经常会看到另外两个常见的注册表：[gcr.io](https://cloud.google.com/container-registry/)，谷歌的容器注册表，以及[quay.io](https://quay.io/)，CoreOS 的容器注册表。其他公司在互联网上提供托管的容器注册表，你也可以自己运行。目前，Docker 和 Quay 都为公共镜像提供免费托管，因此你会经常在文档和示例中看到它们。这三个注册表还提供私有镜像仓库的选项，通常需要相对较小的订阅费用。

公开可用的镜像（以及在这些镜像上进行层叠）的一个好处是，它使得非常容易组合你的镜像，共享底层层。这也意味着这些层可以被检查，并且可以搜索常见的层以查找安全漏洞。有几个旨在帮助提供这些信息的开源项目，还有几家公司成立了帮助协调信息和扫描的公司。如果你为你的镜像订阅了一个镜像仓库，它们通常会在其产品中包括这种漏洞扫描。

作为开发人员，当您在代码中使用库时，您对其操作负有责任。您已经负责熟悉这些库的工作方式（或者不熟悉），并在它们不按预期工作时处理任何问题。通过指定整个容器的灵活性和控制权，您同样负责以相同的方式包含在容器中的所有内容。

很容易忘记软件构建所依赖的层，并且您可能没有时间跟踪所有可能出现的安全漏洞和问题，这些问题可能已经出现在您正在构建的软件中。来自 Clair 等项目的安全扫描（[`github.com/coreos/clair`](https://github.com/coreos/clair)）可以为您提供有关潜在漏洞的出色信息。我建议您考虑利用可以为您提供这些详细信息的服务。

# 创建您的第一个容器

使用 Docker 软件和`docker build`命令很容易创建一个容器。这个命令使用一个详细说明如何创建容器的清单，称为 Dockerfile。

让我们从最简单的容器开始。创建一个名为 Dockerfile 的文件，并将以下内容添加到其中：

```
FROM alpine
CMD ["/bin/sh", "-c", "echo 'hello world'"]
```

然后，调用`build`：

```
docker build .
```

如果您看到这样的响应：

```
"docker build" requires exactly 1 argument.
See 'docker build --help'.
Usage: docker build [OPTIONS] PATH | URL | -
Build an image from a Dockerfile
```

然后，您要么在命令中缺少`.`，要么在与创建 Dockerfile 的目录不同的目录中运行了该命令。`.`告诉`docker`在哪里找到 Dockerfile（`.`表示在当前目录中）。

您应该看到类似以下的输出：

```
Sending build context to Docker daemon  2.048kB
Step 1/2 : FROM alpine
latest: Pulling from library/alpine
88286f41530e: Pull complete
Digest: sha256:f006ecbb824d87947d0b51ab8488634bf69fe4094959d935c0c103f4820a417d
Status: Downloaded newer image for alpine:latest
 ---> 76da55c8019d
Step 2/2 : CMD /bin/sh -c echo 'hello world'
 ---> Running in 89c04e8c5d87
 ---> f5d273aa2dcb
Removing intermediate container 89c04e8c5d87
Successfully built f5d273aa2dcb
```

这个图像只有一个 ID，`f5d273aa2dcb`，没有名称，但这对我们来说已经足够了解它是如何工作的。如果您在本地运行此示例，您将获得一个唯一标识容器图像的不同 ID。您可以使用`docker run f5d273aa2dcb`命令在容器图像中运行代码。这应该会导致您看到以下输出：

```
hello world
```

花点时间在刚刚创建的图像上运行`docker history f5d273aa2dcb`和`docker inspect f5d273aa2dcb`。

完成后，我们可以使用以下命令删除刚刚创建的 Docker 图像：

```
docker rmi **f5d273aa2dcb** 
```

如果您在删除图像时遇到错误，这可能是因为您有一个引用本地图像的已停止容器，您可以通过添加`-f`来强制删除。例如，强制删除本地图像的命令将是：

```
docker rmi -f f5d237aa2dcb
```

# Dockerfile 命令

Docker 有关于如何编写 Dockerfile 的文档，网址是[`docs.docker.com/engine/reference/builder/`](https://docs.docker.com/engine/reference/builder/)，以及他们推荐的一套最佳实践，网址是[`docs.docker.com/engine/userguide/eng-image/dockerfile_best-practices/`](https://docs.docker.com/engine/userguide/eng-image/dockerfile_best-practices/)。我们将介绍一些常见且重要的命令，以便你能够构建自己的容器镜像。

以下是一些重要的 Dockerfile 构建命令，你应该知道：

1.  `FROM` ([`docs.docker.com/engine/reference/builder/#from`](https://docs.docker.com/engine/reference/builder/#from)): `FROM`描述了你用作构建容器基础的图像，并且通常是 Dockerfile 中的第一个命令。Docker 最佳实践鼓励使用 Debian 作为基础 Linux 发行版。正如你之前从我的示例中看到的，我更喜欢使用 Alpine Linux，因为它非常紧凑。你也可以使用 Ubuntu、Fedora 和 CentOS，它们都是更大的图像，并在其基本图像中包含了更多的软件。如果你已经熟悉某个 Linux 发行版及其使用的工具，那么我建议你利用这些知识来制作你的第一个容器。你还经常可以找到专门构建的容器来支持你正在使用的语言，比如 Node 或 Python。在撰写本文时（2017 年秋），我下载了各种这些图像来展示它们的相对大小：

```
REPOSITORY     TAG         IMAGE ID        CREATED          SIZE
alpine         latest      76da55c8019d    2 days ago       3.97MB
debian         latest      72ef1cf971d1    2 days ago       100MB
fedora         latest      ee17cf9e0828    2 days ago       231MB
centos         latest      196e0ce0c9fb    27 hours ago     197MB
ubuntu         latest      8b72bba4485f    2 days ago       120MB
ubuntu         16.10       7d3f705d307c    8 weeks ago      107MB
python         latest      26acbad26a2c    2 days ago       690MB
node           latest      de1099630c13    24 hours ago     673MB
java           latest      d23bdf5b1b1b    8 months ago     643MB
```

正如你所看到的，这些图像的大小差异很大。

你可以在[`hub.docker.com/explore/`](https://hub.docker.com/explore/)上探索这些（以及各种其他基本图像）。

1.  `RUN` ([`docs.docker.com/engine/reference/builder/#run`](https://docs.docker.com/engine/reference/builder/#run)): `RUN`描述了您在构建的容器映像中运行的命令，最常用于添加依赖项或其他库。如果您查看其他人创建的 Dockerfile，通常会看到`RUN`命令用于使用诸如`apt-get install ...`或`rpm -ivh ...`的命令安装库。使用的命令取决于基本映像的选择；例如，`apt-get`在 Debian 和 Ubuntu 基本映像上可用，但在 Alpine 或 Fedora 上不可用。如果您输入一个不可用的`RUN`命令（或只是打字错误），那么在运行`docker build`命令时会看到错误。例如，在构建 Dockerfile 时：

```
FROM alpine
RUN apt-get install nodejs
Results in the following output:
Sending build context to Docker daemon  2.048kB
Step 1/2 : FROM alpine
 ---> 76da55c8019d
Step 2/2 : RUN apt-get install nodejs
 ---> Running in 58200129772d
/bin/sh: apt-get: not found
```

`/bin/sh -c apt-get install nodejs` 命令返回了非零代码：`127`。

1.  `ENV` ([`docs.docker.com/engine/reference/builder/#env`](https://docs.docker.com/engine/reference/builder/#env)): `ENV`定义了将在容器映像中持久存在并在调用软件之前设置的环境变量。这些也在创建容器映像时设置，这可能会导致意想不到的影响。例如，如果您需要为特定的`RUN`命令设置环境变量，最好是使用单个`RUN`命令而不是使用`ENV`命令来定义它。例如，在 Debian 基础映像上使用`ENV DEBIAN_FRONTEND`非交互可能会混淆后续的`RUN apt-get install …`命令。在您想要为特定的`RUN`命令启用它的情况下，您可以通过在单个`RUN`命令前临时添加环境变量来实现。例如：

```
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y ...
```

1.  `COPY` ([`docs.docker.com/engine/reference/builder/#copy`](https://docs.docker.com/engine/reference/builder/#copy)): `COPY`（或`ADD`命令）是将您自己的本地文件添加到容器中的方法。这通常是将代码复制到容器映像中运行的最有效方式。您可以复制整个目录或单个文件。除了`RUN`命令之外，这可能是您使用代码创建容器映像的大部分工作。

1.  `WORKDIR` ([`docs.docker.com/engine/reference/builder/#workdir`](https://docs.docker.com/engine/reference/builder/#workdir))：`WORKDIR`创建一个本地目录，然后将该目录作为以后所有命令（`RUN`，`COPY`等）的基础。对于期望从本地或相对目录运行的`RUN`命令，例如 Node.js `npm`等安装工具，这可能非常方便。

1.  `LABEL` ([`docs.docker.com/engine/reference/builder/#label`](https://docs.docker.com/engine/reference/builder/#label))：`LABEL`添加的值可在`docker inspect`中看到，并通常用作容器内部的责任人或内容的参考。`MAINTAINER`命令以前非常常见，但已被`LABEL`命令取代。标签是基于基本镜像构建的，并且是可累加的，因此您添加的任何标签都将与您使用的基本镜像的标签一起包含在内。

1.  `CMD` ([`docs.docker.com/engine/reference/builder/#cmd`](https://docs.docker.com/engine/reference/builder/#cmd))和`ENTRYPOINT` ([`docs.docker.com/engine/reference/builder/#entrypoint`](https://docs.docker.com/engine/reference/builder/#entrypoint))：`CMD`（和`ENTRYPOINT`命令）是您指定当有人运行容器时要运行什么的方式。最常见的格式是 JSON 数组，其中第一个元素是要调用的命令，而第二个及以后的元素是该命令的参数。`CMD`和`ENTRYPOINT`旨在单独使用，这种情况下，您可以使用`CMD`或`ENTRYPOINT`来指定要运行的可执行文件和所有参数，或者一起使用，这种情况下，`ENTRYPOINT`应该只是可执行文件，而`CMD`应该是该可执行文件的参数。

# 示例 - Python/Flask 容器镜像

为了详细了解如何使用 Kubernetes，我创建了两个示例应用程序，您可以下载或复制以便跟随并尝试这些命令。其中一个是使用 Flask 库的非常简单的 Python 应用程序。示例应用程序直接来自 Flask 文档（[`flask.pocoo.org/docs/0.12/`](http://flask.pocoo.org/docs/0.12/)）。

您可以从 GitHub 上下载这些代码，网址为[`github.com/kubernetes-for-developers/kfd-flask/tree/first_container`](https://github.com/kubernetes-for-developers/kfd-flask/tree/first_container)。由于我们将不断改进这些文件，因此此处引用的代码可在`first_container`标签处获得。如果您想使用 Git 获取这些文件，可以运行以下命令：

```
git clone https://github.com/kubernetes-for-developers/kfd-flask
```

然后，进入存储库并检出标签：

```
cd kfd-flask
git checkout tags/first_container
```

让我们从查看 Dockerfile 的内容开始，该文件定义了构建到容器中的内容以及构建过程。

我们创建这个 Dockerfile 的目标是：

+   获取并安装底层操作系统的任何安全补丁

+   安装我们需要用来运行代码的语言或运行时

+   安装我们的代码中未直接包含的任何依赖项

+   将我们的代码复制到容器中

+   定义如何以及何时运行

```
FROM alpine
# load any public updates from Alpine packages
RUN apk update
# upgrade any existing packages that have been updated
RUN apk upgrade
# add/install python3 and related libraries
# https://pkgs.alpinelinux.org/package/edge/main/x86/python3
RUN apk add python3
# make a directory for our application
RUN mkdir -p /opt/exampleapp
# move requirements file into the container
COPY . /opt/exampleapp/
# install the library dependencies for this application
RUN pip3 install -r /opt/exampleapp/requirements.txt
ENTRYPOINT ["python3"]
CMD ["/opt/exampleapp/exampleapp.py"]
```

此容器基于 Alpine Linux。我欣赏容器的小巧尺寸，并且容器中没有多余的软件。您将看到一些可能不熟悉的命令，特别是`apk`命令。这是一个命令行工具，用于帮助安装、更新和删除 Alpine Linux 软件包。这些命令更新软件包存储库，升级镜像中安装的和预先存在的所有软件包，然后从软件包中安装 Python 3。

如果您已经熟悉 Debian 命令（如`apt-get`）或 Fedora/CentOS 命令（如`rpm`），那么我建议您使用这些基本 Linux 容器进行您自己的工作。

接下来的两个命令在容器中创建一个目录`/opt/exampleapp`来存放我们的源代码，并将所有内容复制到指定位置。`COPY`命令将本地目录中的所有内容添加到容器中，这可能比我们需要的要多。您可以在将来创建一个名为`.dockerignore`的文件，该文件将根据模式`ignore`一组文件，以便在`COPY`命令中忽略一些不想包含的常见文件。

接下来，您将看到一个`RUN`命令，该命令安装应用程序的依赖项，这些依赖项来自名为`requirements.txt`的文件，该文件包含在源代码库中。在这种情况下，将依赖项保存在这样的文件中是一个很好的做法，而`pip`命令就是为了支持这样做而创建的。

最后两个命令分别利用了 `ENTRYPOINT` 和 `CMD`。对于这个简单的例子，我可以只使用其中一个。两者都包括在内是为了展示它们如何一起使用，`CMD` 本质上是传递给 `ENTRYPOINT` 中定义的可执行文件的参数。

# 构建容器

我们将使用 `docker build` 命令来创建容器。在终端窗口中，切换到包含 Dockerfile 的目录，并运行以下命令：

```
docker build .
```

您应该看到类似以下的输出：

```
Sending build context to Docker daemon    107kB
Step 1/9 : FROM alpine
 ---> 76da55c8019d
Step 2/9 : RUN apk update
 ---> Running in f72d5991a7cd
fetch http://dl-cdn.alpinelinux.org/alpine/v3.6/main/x86_64/APKINDEX.tar.gz
fetch http://dl-cdn.alpinelinux.org/alpine/v3.6/community/x86_64/APKINDEX.tar.gz
v3.6.2-130-gfde2d8ebb8 [http://dl-cdn.alpinelinux.org/alpine/v3.6/main]
v3.6.2-125-g93038b573e [http://dl-cdn.alpinelinux.org/alpine/v3.6/community]
OK: 8441 distinct packages available
 ---> b44cd5d0ecaa
Removing intermediate container f72d5991a7cd
```

Dockerfile 中的每一步都会反映在 Docker 构建镜像时发生的输出，对于更复杂的 Dockerfile，输出可能会非常庞大。在完成构建过程时，它会报告总体成功或失败，并且还会报告容器的 ID：

```
Step 8/9 : ENTRYPOINT python3
 ---> Running in 14c58ace8b14
 ---> 0ac8be8b042d
Removing intermediate container 14c58ace8b14
Step 9/9 : CMD /opt/exampleapp/exampleapp.py
 ---> Running in e769a65fedbc
 ---> b704504464dc
Removing intermediate container e769a65fedbc
Successfully built 4ef370855f35
```

当我们构建容器时，如果没有其他信息，它会在本地创建一个我们可以使用的镜像（它有一个 ID），但它没有名称或标签。在选择名称时，通常要考虑您托管容器镜像的位置。在这种情况下，我使用的是 CoreOS 的 Quay.io 服务，该服务为开源容器镜像提供免费托管。

要为刚刚创建的镜像打标签，我们可以使用 `docker tag` 命令：

```
docker tag 4ef370855f35 quay.io/kubernetes-for-developers/flask
```

这个标签包含三个相关部分。第一个 [quay.io](http://quay.io) 是容器注册表。第二个 (`kubernetes-for-developers`) 是您容器的命名空间，第三个 (`flask`) 是容器的名称。我们没有为容器指定任何特定的标签，所以 `docker` 命令将使用 latest。

您应该使用标签来表示发布或开发中的其他时间点，以便您可以轻松地返回到这些时间点，并使用 latest 来表示您最近的开发工作，因此让我们也将其标记为一个特定的版本：

```
docker tag 4ef370855f35 quay.io/kubernetes-for-developers/flask:0.1.0
```

当您与他人共享镜像时，明确指出您正在使用的镜像是一个非常好的主意。一般来说，只考虑自己使用代码，每当与其他人共享镜像时，都要使用明确的标签。标签不一定是一个版本，虽然它的格式有限制，但几乎可以是任何字符串。

您可以使用 `docker push` 命令将已经标记的镜像传输到容器仓库。您需要先登录到您的容器仓库：

```
docker login quay.io
```

然后你可以推送这个镜像：

```
docker push quay.io/kubernetes-for-developers/flask
```

推送是指一个仓库，`[quay.io/kubernetes-for-developers/flask]`：

```
0b3b7598137f: Pushed
602c2b5ffa76: Pushed 217607c1e257: Pushed
40ca06be4cf4: Pushed 5fbd4bb748e7: Pushed
0d2acef20dc1: Pushed
5bef08742407: Pushed
latest: digest: sha256:de0c5b85893c91062fcbec7caa899f66ed18d42ba896a47a2f4a348cbf9b591f size: 5826
```

通常，您希望从一开始就使用标签构建您的容器，而不是必须执行额外的命令。为此，您可以使用`-t <your_name>`选项将标签信息添加到`build`命令中。对于本书中的示例，我使用的名称是`kubernetes-for-developers`，因此我一直在使用以下命令构建示例：

```
docker build -t quay.io/kubernetes-for-developers/flask .
```

如果您正在按照此示例操作，请在先前命令中的`quay.io/kubernetes-for-developers/flask .`处使用您自己的值。您应该看到以下输出：

```
Sending build context to Docker daemon    107kB
Step 1/9 : FROM alpine
 ---> 76da55c8019d
Step 2/9 : RUN apk update
 ---> Using cache
 ---> b44cd5d0ecaa
Step 3/9 : RUN apk upgrade
 ---> Using cache
 ---> 0b1caea1a24d
Step 4/9 : RUN apk add python3
 ---> Using cache
 ---> 1e29fcb9621d
Step 5/9 : RUN mkdir -p /opt/exampleapp
 ---> Using cache
 ---> 622a12042892
Step 6/9 : COPY . /opt/exampleapp/
 ---> Using cache
 ---> 7f9115a50a0a
Step 7/9 : RUN pip3 install -r /opt/exampleapp/requirements.txt
 ---> Using cache
 ---> d8ef21ee1209
Step 8/9 : ENTRYPOINT python3
 ---> Using cache
 ---> 0ac8be8b042d
Step 9/9 : CMD /opt/exampleapp/exampleapp.py
 ---> Using cache
 ---> b704504464dc
Successfully built b704504464dc
Successfully tagged quay.io/kubernetes-for-developers/flask:latest
```

花点时间阅读该输出，并注意在几个地方报告了`Using cache`。您可能还注意到，该命令比您第一次构建镜像时更快。

这是因为 Docker 尝试重用任何未更改的层，以便它不必重新创建该工作。由于我们刚刚执行了所有这些命令，它可以使用在创建上一个镜像时制作的缓存中的层。

如果运行`docker images`命令，您现在应该看到它被列出：

```
REPOSITORY                                TAG       IMAGE ID      CREATED          SIZE
quay.io/kubernetes-for-developers/flask   0.1.0     b704504464dc  2 weeks ago         70.1MB
quay.io/kubernetes-for-developers/flask   latest    b704504464dc  2 weeks ago         70.1MB
```

随着您继续使用容器映像来存储和部署您的代码，您可能希望自动化创建映像的过程。作为一般模式，一个良好的构建过程应该是：

+   从源代码控制获取代码

+   `docker build`

+   `docker tag`

+   `docker push`

这是我们在这些示例中使用的过程，您可以使用最适合您的工具自动化这些命令。我建议您设置一些可以快速且一致地在命令行上运行的东西。

# 运行您的容器

现在，让我们运行刚刚制作的容器。我们将使用`kubectl run`命令来指定最简单的部署——只是容器：

```
kubectl run flask --image=quay.io/kubernetes-for-developers/flask:latest --port=5000 --save-config
deployment “flask” created
```

要查看这是在做什么，我们需要向集群询问我们刚刚创建的资源的当前状态。当我们使用`kubectl run`命令时，它将隐式为我们创建一个 Deployment 资源，并且正如您在上一章中学到的，Deployment 中有一个 ReplicaSet，ReplicaSet 中有一个 Pod：

```
kubectl get deployments
NAME      DESIRED   CURRENT   UP-TO-DATE   AVAILABLE   AGE
flask     1         1         1            1           20h
kubectl get pods
NAME                     READY     STATUS    RESTARTS   AGE
flask-1599974757-b68pw   1/1       Running   0          20h
```

我们可以通过请求与 Kubernetes 部署资源`flask`相关联的原始数据来获取有关此部署的详细信息：

```
kubectl get deployment flask -o json
```

我们也可以轻松地请求以`YAML`格式的信息，或者查询这些细节的子集，利用 JsonPath 或`kubectl`命令的其他功能。JSON 输出将非常丰富。它将以一个指示来自 Kubernetes 的 apiVersion 的键开始，资源的种类以及关于资源的元数据：

```
{
    "apiVersion": "extensions/v1beta1",
    "kind": "Deployment",
    "metadata": {
        "annotations": {
            "deployment.kubernetes.io/revision": "1"
        },
        "creationTimestamp": "2017-09-16T00:40:44Z",
        "generation": 1,
        "labels": {
            "run": "flask"
        },
        "name": "flask",
        "namespace": "default",
        "resourceVersion": "51293",
        "selfLink": "/apis/extensions/v1beta1/namespaces/default/deployments/flask",
        "uid": "acbb0128-9a77-11e7-884c-0aef48c812e4"
    },
```

在此之下通常是部署本身的规范，其中包含了大部分正在运行的核心内容。

```
    "spec": {
        "replicas": 1,
        "selector": {
            "matchLabels": {
                "run": "flask"
            }
        },
        "strategy": {
            "rollingUpdate": {
                "maxSurge": 1,
                "maxUnavailable": 1
            },
            "type": "RollingUpdate"
        },
        "template": {
            "metadata": {
                "creationTimestamp": null,
                "labels": {
                    "run": "flask"
                }
            },
            "spec": {
                "containers": [
                    {
                        "image": "quay.io/kubernetes-for-developers/flask:latest",
                        "imagePullPolicy": "Always",
                        "name": "flask",
                        "ports": [
                            {
                                "containerPort": 5000,
                                "protocol": "TCP"
                            }
                        ],
                        "resources": {},
                        "terminationMessagePath": "/dev/termination-log",
                        "terminationMessagePolicy": "File"
                    }
                ],
                "dnsPolicy": "ClusterFirst",
                "restartPolicy": "Always",
                "schedulerName": "default-scheduler",
                "securityContext": {},
                "terminationGracePeriodSeconds": 30
            }
        }
    },
```

最后一部分通常是状态，它指示了部署的当前状态，即您请求信息的时间。

```
    "status": {
        "availableReplicas": 1,
        "conditions": [
            {
                "lastTransitionTime": "2017-09-16T00:40:44Z",
                "lastUpdateTime": "2017-09-16T00:40:44Z",
                "message": "Deployment has minimum availability.",
                "reason": "MinimumReplicasAvailable",
                "status": "True",
                "type": "Available"
            }
        ],
        "observedGeneration": 1,
        "readyReplicas": 1,
        "replicas": 1,
        "updatedReplicas": 1
    }
}
```

在 Kubernetes 中运行 Pod 时，请记住它是在一个沙盒中运行的，与世界其他部分隔离开来。Kubernetes 有意这样做，这样您就可以指定 Pod 应该如何连接以及集群外部可以访问什么。我们将在后面的章节中介绍如何设置外部访问。与此同时，您可以利用`kubectl`中的两个命令直接从开发机器获取访问权限：`kubectl port-forward`或`kubectl proxy`。

这两个命令都是通过将代理从您的本地开发机器到 Kubernetes 集群，为您提供对正在运行的代码的私人访问权限。`port-forward`命令将打开一个特定的 TCP（或 UDP）端口，并安排所有流量转发到集群中的 Pod。代理命令使用已经存在的 HTTP 代理来转发 HTTP 流量进出您的 Pod。这两个命令都依赖于知道 Pod 名称来建立连接。

# Pod 名称

由于我们正在使用一个 Web 服务器，使用代理是最合理的，因为它将根据 Pod 的名称将 HTTP 流量转发到一个 URL。在这之前，我们将使用`port-forward`命令，如果您的编写不使用 HTTP 协议，这将更相关。

你需要的关键是创建的 Pod 的名称。当我们之前运行`kubectl get pods`时，你可能注意到名称不仅仅是`flask`，而是在名称中包含了一些额外的字符：`flask-1599974757-b68pw`。当我们调用`kubectl run`时，它创建了一个部署，其中包括一个包裹在 Pod 周围的 Kubernetes ReplicaSet。名称的第一部分（`flask`）来自部署，第二部分（`1599974757`）是分配给创建的 ReplicaSet 的唯一名称，第三部分（`b68pw`）是分配给创建的 Pod 的唯一名称。如果你运行以下命令：

```
kubectl get replicaset 
```

结果将显示副本集：

```
NAME               DESIRED   CURRENT   READY     AGE
flask-1599974757   1         1         1         21h
```

你可以看到 ReplicaSet 名称是 Pod 名称的前两部分。

# 端口转发

现在我们可以使用该名称来要求`kubectl`设置一个代理，将我们指定的本地端口上的所有流量转发到我们确定的 Pod 关联的端口。通过使用以下命令查看使用部署创建的 Pod 的完整名称：

```
kubectl get pods
```

在我的例子中，结果是`flask-1599974757-b68pw`，然后可以与`port-forward`命令一起使用：

```
kubectl port-forward flask-1599974757-b68pw 5000:5000
```

输出应该类似于以下内容：

```
Forwarding from 127.0.0.1:5000 -> 5000
Forwarding from [::1]:5000 -> 5000
```

这将转发在本地机器上创建的任何流量到 Pod`flask-1599974757-b68pw`的 TCP 端口`5000`上的 TCP 端口`5000`。

你会注意到你还没有回到命令提示符，这是因为命令正在积极运行，以保持我们请求的特定隧道活动。如果我们取消或退出`kubectl`命令，通常通过按*Ctrl* + C，那么端口转发将立即结束。`kubectl proxy`的工作方式相同，因此当你使用诸如`kubectl port-forward`或`kubectl proxy`的命令时，你可能希望打开另一个终端窗口单独运行该命令。

当命令仍在运行时，打开浏览器并输入此 URL：`http://localhost:5000`。响应应该返回`Index Page`。当我们调用`kubectl run`命令时，我特意选择端口`5000`来匹配 Flask 的默认端口。

# 代理

你可以使用的另一个命令来访问你的 Pod 是`kubectl proxy`命令。代理不仅提供对你的 Pod 的访问，还提供对所有 Kubernetes API 的访问。要调用代理，运行以下命令：

```
kubectl proxy
```

输出将显示类似于以下内容：

```
Starting to serve on 127.0.0.1:8001
```

与`port-forward`命令一样，在代理终止之前，您在终端窗口中将不会收到提示。在它处于活动状态时，您可以通过这个代理访问 Kubernetes REST API 端点。打开浏览器，输入 URL `http://localhost:8001/`。

您应该看到一个类似以下的 JSON 格式的 URL 列表：

```
{
 "paths": [ "/api", "/api/v1", "/apis", "/apis/", "/apis/admissionregistration.k8s.io", "/apis/admissionregistration.k8s.io/v1alpha1", "/apis/apiextensions.k8s.io", "/apis/apiextensions.k8s.io/v1beta1", "/apis/apiregistration.k8s.io",
```

这些都是直接访问 Kubernetes 基础设施。其中一个 URL 是`/api/v1` - 尽管它没有被明确列出，它使用 Kubernetes API 服务器来根据名称为 Pod 提供代理。当我们调用我们的`run`命令时，我们没有指定一个命名空间，所以它使用了默认的命名空间，称为`default`。查看 Pod 的 URL 模式是：

`http://localhost:8001/api/v1/proxy/namespaces/<NAME_OF_NAMESPACE>/pods/<POD_NAME>/`

在我们的 Pod 的情况下，这将是：

`http://localhost:8001/api/v1/proxy/namespaces/default/pods/flask-1599974757-b68pw/`

如果您在浏览器中打开一个由 Kubernetes 集群分配的 Pod 名称创建的 URL，它应该显示与使用`port-forward`命令看到的相同的输出。

# 代理是如何知道连接到容器上的端口 5000 的？

当您运行容器时，Kubernetes 并不会神奇地知道您的代码正在侦听哪些 TCP 端口。当我们使用`kubectl run`命令创建此部署时，我们在该命令的末尾添加了`--port=5000`选项。Kubernetes 使用这个选项来知道程序应该在端口`5000`上侦听 HTTP 流量。如果您回顾一下`kubectl get deployment -o json`命令的输出，您会看到其中一个部分在`containers`键下包括我们提供的镜像、部署的名称和一个数据结构，指示访问容器的默认端口为`5000`。如果我们没有提供额外的细节，代理将假定我们希望在端口`80`访问容器。由于我们的开发容器上没有在端口`80`上运行任何内容，您会看到类似于以下的错误：

```
Error: 'dial tcp 172.17.0.4:80: getsockopt: connection refused'
Trying to reach: 'http://172.17.0.4/'
```

# 从您的应用程序获取日志

有更多的方法可以与在容器中运行的代码进行交互，我们将在以后的章节中介绍。如果您运行的代码没有侦听 TCP 套接字以提供 HTTP 流量，或者类似的内容，那么通常您希望查看您的代码创建的输出以知道它是否正在运行。

容器专门设置为捕获您指定的可执行文件的 STDOUT 和 STDERR 的任何输出，并将其捕获到日志中，可以使用另一个`kubectl`命令检索这些日志：`kubectl logs`。与`proxy`和`port-forward`命令一样，此命令需要知道您要交互的 Pod 的名称。

运行以下命令：

```
kubectl logs flask-1599974757-b68pw
```

您应该看到类似以下的输出：

```
 * Running on http://0.0.0.0:5000/ (Press CTRL+C to quit)
 * Restarting with stat
 * Debugger is active!
 * Debugger PIN: 996-805-904
```

# 示例 - Node.js/Express 容器映像

此示例遵循与 Python 示例相同的模式，即使用 Express 库构建的简单 Node.js 应用程序，以详细介绍如何使用 Kubernetes。如果您更熟悉 JavaScript 开发，则此示例可能更有意义。示例应用程序直接来自 Express 文档([`expressjs.com/en/starter/generator.html`](http://flask.pocoo.org/docs/0.12/))。

您可以从 GitHub 下载此代码副本[`github.com/kubernetes-for-developers/kfd-nodejs/tree/first_container`](https://github.com/kubernetes-for-developers/kfd-nodejs/tree/first_container)。由于我们将使这些文件发展，此处引用的代码可在`first_container`标签处获得。如果要使用 Git 检索这些文件，可以使用以下命令：

```
git clone https://github.com/kubernetes-for-developers/kfd-nodejs
cd kfd-nodejs
git checkout tags/first_container
```

与 Python 示例一样，我们将从 Dockerfile 开始。提醒一下，这是定义构建到容器中的内容以及构建方式的文件。此 Dockerfile 的目标是：

+   获取并安装基础操作系统的任何关键安全补丁

+   安装我们将需要用来运行我们的代码的语言或运行时

+   安装我们的代码中未直接包含的任何依赖项

+   将我们的代码复制到容器中

+   定义如何以及何时运行

```
FROM alpine
# load any public updates from Alpine packages
RUN apk update
# upgrade any existing packages that have been updated
RUN apk upgrade
# add/install python3 and related libraries
# https://pkgs.alpinelinux.org/package/edge/main/x86/python3
RUN apk add nodejs nodejs-npm
# make a directory for our application
WORKDIR /src
# move requirements file into the container
COPY package.json .
COPY package-lock.json .
# install the library dependencies for this application
RUN npm install --production
# copy in the rest of our local source
COPY . .
# set the debug environment variable
ENV DEBUG=kfd-nodejs:*
CMD ["npm", "start"]
```

与 Python 示例一样，此容器基于 Alpine Linux。您将看到一些可能不熟悉的命令，特别是`apk`命令。作为提醒，此命令用于安装、更新和删除 Alpine Linux 软件包。这些命令更新 Alpine 软件包存储库，升级图像中安装的所有已安装和预先存在的软件包，然后从软件包安装`nodejs`和`npm`。这些步骤基本上使我们得到一个可以运行 Node.js 应用程序的最小容器。

接下来的命令在容器中创建一个目录`/src`来存放我们的源代码，复制`package.json`文件，然后使用`npm`安装运行代码所需的依赖项。`npm install`命令与`--production`选项一起使用，只安装`package.json`中列出的运行代码所需的项目 - 开发依赖项被排除在外。Node.js 通过其`package.json`格式轻松而一致地维护依赖关系，将生产所需的依赖与开发所需的依赖分开是一个良好的做法。

最后两个命令利用了`ENV`和`CMD`。这与 Python 示例不同，我在 Python 示例中使用了`CMD`和`ENTRYPOINT`来突出它们如何一起工作。在这个示例中，我使用`ENV`命令将`DEBUG`环境变量设置为与 Express 文档中示例指令匹配。然后`CMD`包含一个启动我们代码的命令，简单地利用`npm`运行`package.json`中定义的命令，并使用之前的`WORKDIR`命令为该调用设置本地目录。

# 构建容器

我们使用相同的`docker build`命令来创建容器：

```
docker build .
```

你应该看到类似以下的输出：

```
Sending build context to Docker daemon  197.6kB
Step 1/11 : FROM alpine
 ---> 76da55c8019d
Step 2/11 : RUN apk update
 ---> Using cache
 ---> b44cd5d0ecaa
```

就像你在基于 Python 的示例中看到的那样，Dockerfile 中的每个步骤都会反映出输出，显示 Docker 根据你的指令（Dockerfile）构建容器镜像的过程：

```
Step 9/11 : COPY . .
 ---> 6851a9088ce3
Removing intermediate container 9fa9b8b9d463
Step 10/11 : ENV DEBUG kfd-nodejs:*
 ---> Running in 663a2cd5f31f
 ---> 30c3b45c4023
Removing intermediate container 663a2cd5f31f
Step 11/11 : CMD npm start
 ---> Running in 52cf9638d065
 ---> 35d03a9d90e6
Removing intermediate container 52cf9638d065
Successfully built 35d03a9d90e6
```

与 Python 示例一样，这将构建一个只有 ID 的容器。这个示例还利用 Quay 来公开托管图像，因此我们将适当地获取图像，以便上传到 Quay：

```
docker tag 35d03a9d90e6 quay.io/kubernetes-for-developers/nodejs
```

与 Python 示例一样，标签包含三个相关部分 - [quay.io](http://quay.io) 是容器注册表。第二个（`kubernetes-for-developers`）是容器的命名空间，第三个（`nodejs`）是容器的名称。与 Python 示例一样，使用相同的命令上传容器，引用`nodejs`而不是`flask`：

```
docker login quay.io docker push quay.io/kubernetes-for-developers/nodejs
```

```
The push refers to a repository [quay.io/kubernetes-for-developers/nodejs]
0b6165258982: Pushed
8f16769fa1d0: Pushed
3b43ed4da811: Pushed
9e4ead6d58f7: Pushed
d56b3cb786f1: Pushedfad7fd538fb6: Pushing [==================>                                ]  11.51MB/31.77MB
5fbd4bb748e7: Pushing [==================================>                ]  2.411MB/3.532MB
0d2acef20dc1: Pushing [==================================================>]  1.107MB
5bef08742407: Pushing [================>                                  ]  1.287MB/3.966MB
```

完成后，你应该看到类似以下的内容：

```
The push refers to a repository [quay.io/kubernetes-for-developers/nodejs]
0b6165258982: Pushed
8f16769fa1d0: Pushed
3b43ed4da811: Pushed
9e4ead6d58f7: Pushed
d56b3cb786f1: Pushed
fad7fd538fb6: Pushed
5fbd4bb748e7: Pushed
0d2acef20dc1: Pushed
5bef08742407: Pushed
latest: digest: sha256:0e50e86d27a4b29b5b10853d631d8fc91bed9a37b44b111111dcd4fd9f4bc723 size: 6791
```

与 Python 示例一样，你可能希望在同一命令中构建和标记。对于 Node.js 示例，该命令将是：

```
docker build -t quay.io/kubernetes-for-developers/nodejs:0.2.0 .
```

如果在构建图像后立即运行，应该显示类似以下的输出：

```
Sending build context to Docker daemon  197.6kB
Step 1/11 : FROM alpine
 ---> 76da55c8019d
Step 2/11 : RUN apk update
 ---> Using cache
 ---> b44cd5d0ecaa
Step 3/11 : RUN apk upgrade
 ---> Using cache
 ---> 0b1caea1a24d
Step 4/11 : RUN apk add nodejs nodejs-npm
 ---> Using cache
 ---> 193d3570516a
Step 5/11 : WORKDIR /src
 ---> Using cache
 ---> 3a5d78afa1be
Step 6/11 : COPY package.json .
 ---> Using cache
 ---> 29724b2bd1b9
Step 7/11 : COPY package-lock.json .
 ---> Using cache
 ---> ddbcb9af6ffc
Step 8/11 : RUN npm install --production
 ---> Using cache
 ---> 1556a20af49a
Step 9/11 : COPY . .
 ---> Using cache
 ---> 6851a9088ce3
Step 10/11 : ENV DEBUG kfd-nodejs:*
 ---> Using cache
 ---> 30c3b45c4023
Step 11/11 : CMD npm start
 ---> Using cache
 ---> 35d03a9d90e6
Successfully built 35d03a9d90e6
Successfully tagged quay.io/kubernetes-for-developers/nodejs:latest
```

与使用 Docker 缓存的图像层相比，速度会快得多，因为它使用了先前构建的图像层。

如果运行`docker images`命令，你现在应该能看到它被列出来了：

```
REPOSITORY                                TAG       IMAGE ID      CREATED          SIZE
quay.io/kubernetes-for-developers/nodejs  0.2.0    46403c409d1f  4 minutes ago    81.9MB
```

如果你将自己的镜像推送到`quay.io`作为容器仓库，除了这些命令，你可能需要登录网站并将镜像设为公开。默认情况下，`quay.io`会保持镜像私有，即使是公共的，直到你在他们的网站上批准它们的公开。

# 运行你的容器

现在，让我们运行刚刚创建的容器。我们将使用`kubectl run`命令，就像 Python 示例一样，但是用`nodejs`替换 flask 来指定我们刚刚创建和上传的容器：

```
kubectl run nodejs --image=quay.io/kubernetes-for-developers/nodejs:0.2.0 --port=3000
deployment “nodejs” created
```

为了查看它的运行情况，我们需要向集群请求刚刚创建的资源的当前状态：

```
kubectl get deployments
NAME      DESIRED   CURRENT   UP-TO-DATE   AVAILABLE   AGE
nodejs    1         1         1            1           1d
kubectl get pods
NAME                     READY     STATUS    RESTARTS   AGE
nodejs-568183341-2bw5v   1/1       Running   0          1d
```

`kubectl run`命令不受语言限制，并且与 Python 示例的方式相同。在这种情况下创建的简单部署被命名为`nodejs`，我们可以请求与之前 Python 示例相同类型的信息：

```
kubectl get deployment nodejs -o json
```

JSON 输出应该会非常详细，并且会有多个部分。输出的顶部会有关于部署的`apiVersion`，`kind`和`metadata`：

```
{
    "apiVersion": "extensions/v1beta1",
    "kind": "Deployment",
    "metadata": {
        "annotations": {
            "deployment.kubernetes.io/revision": "1"
        },
        "creationTimestamp": "2017-09-16T10:06:30Z",
        "generation": 1,
        "labels": {
            "run": "nodejs"
        },
        "name": "nodejs",
        "namespace": "default",
        "resourceVersion": "88886",
        "selfLink": "/apis/extensions/v1beta1/namespaces/default/deployments/nodejs",
        "uid": "b5d94f83-9ac6-11e7-884c-0aef48c812e4"
    },
```

通常，在这之下会有`spec`，其中包含了你刚刚要求运行的核心内容：

```
    "spec": {
        "replicas": 1,
        "selector": {
            "matchLabels": {
                "run": "nodejs"
            }
        },
        "strategy": {
            "rollingUpdate": {
                "maxSurge": 1,
                "maxUnavailable": 1
            },
            "type": "RollingUpdate"
        },
        "template": {
            "metadata": {
                "creationTimestamp": null,
                "labels": {
                    "run": "nodejs"
                }
            },
            "spec": {
                "containers": [
                    {
                        "image": "quay.io/kubernetes-for-developers/nodejs:0.2.0",
                        "imagePullPolicy": "IfNotPresent",

                        "name": "nodejs",
                        "ports": [
                            {
                                "containerPort": 3000,
                                "protocol": "TCP"
                            }
                        ],
                        "resources": {},
                        "terminationMessagePath": "/dev/termination-log",
                        "terminationMessagePolicy": "File"
                    }
                ],
                "dnsPolicy": "ClusterFirst",
                "restartPolicy": "Always",
                "schedulerName": "default-scheduler",
                "securityContext": {},
                "terminationGracePeriodSeconds": 30
            }
        }
    },
```

最后一部分是`status`，它指示了部署的当前状态（截至请求此信息时）：

```
    "status": {
        "availableReplicas": 1,
        "conditions": [
            {
                "lastTransitionTime": "2017-09-16T10:06:30Z",
                "lastUpdateTime": "2017-09-16T10:06:30Z",
                "message": "Deployment has minimum availability.",
                "reason": "MinimumReplicasAvailable",
                "status": "True",
                "type": "Available"
            }
        ],
        "observedGeneration": 1,
        "readyReplicas": 1,
        "replicas": 1,
        "updatedReplicas": 1
    }
}
```

当 Pod 在 Kubernetes 中运行时，它是在一个与世隔绝的沙盒中运行的。Kubernetes 故意这样做，这样你就可以指定哪些系统可以相互通信，以及可以从外部访问什么。对于大多数集群，Kubernetes 的默认设置允许任何 Pod 与任何其他 Pod 通信。就像 Python 示例一样，你可以利用`kubectl`中的两个命令之一来从开发机器直接访问：`kubectl` port-forward 或`kubectl` proxy。

# 端口转发

现在我们可以使用这个名称来要求`kubectl`设置一个代理，将我们指定的本地端口的所有流量转发到我们确定的 Pod 关联的端口。Node.js 示例在不同的端口上运行（端口`3000`而不是端口`5000`），因此命令需要相应地更新：

```
kubectl port-forward nodejs-568183341-2bw5v 3000:3000
```

输出应该类似于以下内容：

```
Forwarding from 127.0.0.1:3000 -> 3000
Forwarding from [::1]:3000 -> 3000
```

这会将在本地机器上创建的任何流量转发到`nodejs-568183341-2bw5v` Pod 上的 TCP 端口`3000`。

就像 Python 示例一样，因为命令正在运行以保持这个特定的隧道活动，所以你还没有得到一个命令提示符。提醒一下，你可以通过按下 *Ctrl* + *C* 来取消或退出 `kubectl` 命令，端口转发将立即结束。

当命令仍在运行时，打开浏览器并输入此 URL：`http://localhost:3000`。响应应该返回说 `Index Page`。当我们调用 `kubectl run` 命令时，我特意选择端口 `3000` 来匹配 Express 的默认端口。

# 代理

由于这是一个基于 HTTP 的应用程序，我们也可以使用 `kubectl proxy` 命令来访问我们代码的响应：

```
kubectl proxy
```

输出将显示类似于以下内容：

```
Starting to serve on 127.0.0.1:8001
```

提醒一下，在代理终止之前，你不会在终端窗口中得到提示符。就像 Python 示例一样，我们可以根据我们在调用 `kubectl run` 命令时使用的 Pod 名称和命名空间来确定代理将用于转发到我们容器的 URL。由于我们没有指定命名空间，它使用的是默认的 `default`。访问 Pod 的 URL 模式与 Python 示例相同：

`http://localhost:8001/api/v1/proxy/namespaces/<NAME_OF_NAMESPACE>/pods/<POD_NAME>/`

在我们的 Pod 的情况下，这将是：

`http://localhost:8001/api/v1/proxy/namespaces/default/pods/nodejs-568183341-2bw5v/`

如果你在浏览器中打开一个由你的 Kubernetes 集群分配的 Pod 名称创建的 URL，它应该显示与使用 `port-forward` 命令看到的相同的输出。

# 获取应用程序的日志

就像 Python 示例一样，Node.js 示例也会将一些输出发送到 `STDOUT`。由于容器专门设置来捕获你指定的可执行文件的 `STDOUT` 和 `STDERR` 的任何输出，并将其捕获到日志中，相同的命令将起作用，以显示来自 Node.js 应用程序的日志输出：

```
kubectl logs nodejs-568183341-2bw5v
```

这应该显示类似于以下的输出：

```
> kfd-nodejs@0.0.0 start /src
> node ./bin/www
Sat, 16 Sep 2017 10:06:41 GMT kfd-nodejs:server Listening on port 3000
GET / 304 305.615 ms - -
GET /favicon.ico 404 54.056 ms - 855
GET /stylesheets/style.css 200 63.234 ms - 111
GET / 200 48.033 ms - 170
GET /stylesheets/style.css 200 1.373 ms - 111
```

# 给你的容器图像打标签

在 Docker 图像上使用 `:latest` 标签非常方便，但很容易导致混淆，不知道到底在运行什么。如果你使用 `:latest`，那么告诉 Kubernetes 在加载容器时始终尝试拉取新的镜像是一个非常好的主意。我们将在第四章中看到如何设置这一点，*声明式基础设施*，当我们谈论声明性地定义我们的应用程序时。

另一种方法是制作显式标签，使用标签进行构建，并使用`docker tag`将映像标记为`latest`以方便使用，但在提交到源代码控制时保持特定的标签。对于本示例，选择的标签是`0.2.0`，使用语义化版本表示要与容器一起使用的值，并与`git tag`匹配。

在制作这个示例时使用的步骤是：

```
git tag 0.2.0
docker build -t quay.io/kubernetes-for-developers/nodejs:0.2.0 .
git push origin master --tags
docker push quay.io/kubernetes-for-developers/nodejs
```

# 摘要

在本章中，我们回顾了容器的组成，如何在互联网上存储和共享容器，以及一些用于创建自己的容器的命令。然后，我们利用这些知识在 Python 和 Node.js 中进行了示例演示，分别创建了简单的基于 Web 的服务，将它们构建成容器映像，并在 Kubernetes 中运行它们。在下一章中，我们将深入探讨如何与打包成容器的代码进行交互，并探索在开发过程中充分利用容器和 Kubernetes 的技巧。


# 第三章：在 Kubernetes 中与您的代码交互

在上一章中，我们介绍了制作容器镜像，并使用 Python 和 Node.js 创建了简单的示例。在本章中，我们将扩展与正在运行的代码交互的简要介绍，并深入了解如何查看代码的运行情况，运行其他命令，并从这些 Pod 中进行调试的更多细节。

本章的各节包括：

+   编写软件以在 Pod 中运行的实用注释

+   从您的容器和 Pod 中获取日志

+   与正在运行的 Pod 交互

+   Kubernetes 概念—标签和选择器

+   Kubernetes 资源—服务

+   从您的 Pod 中发现服务

# 编写软件以在容器中运行的实用注释

要在开发过程中使用 Kubernetes，其中一个基本要求是在容器中运行代码。正如您所见，这为您的开发过程增加了一些步骤。它还在如何构造代码和与之交互方面增加了一些约束，主要是为了让您能够利用这些约束，让 Kubernetes 来运行进程、连接它们，并协调任何输出。这与许多开发人员习惯的在本地开发机器上运行一个或多个进程，甚至需要额外服务来运行应用程序（如数据库或缓存）的习惯非常不同。

本节提供了一些有关如何更有效地使用容器的提示和建议。

# 获取可执行代码的选项

除了在创建容器时定义的`ENTRYPOINT`和`CMD`之外，容器镜像还可以通过`ENV`命令定义环境变量。`ENTRYPOINT`、`CMD`和环境变量可以在执行时或在定义部署时被覆盖或更新。因此，环境变量成为向容器传递配置的最常见方式之一。

编写软件以利用这些环境变量将是重要的。在创建软件时，请确保您可以利用环境变量以及代码中的命令行参数。大多数语言都有一个库，可以支持选项作为命令行参数或环境变量。

在下一章中，我们将看到如何设置配置并在部署时将其传递给您的容器。

# 构建容器镜像的实用注释

以下是维护容器镜像的建议和实用建议：

+   在源代码存储库中保留一个 Dockerfile。如果您的应用程序源代码本身位于 Git 存储库中，那么在存储库中包含一个 Dockerfile 是非常合理的。您可以引用要从相对目录复制或添加的文件，该目录是您的源代码所在的位置。在存储库的根目录中看到 Dockerfile 是很常见的，或者如果您正在从一个包含许多项目的 monorepo 中工作，可以考虑在与项目源代码相同的目录中创建一个 Docker 目录：

+   如果您想利用 Docker Hub、Quay 或其他容器存储库上的自动 Docker 构建，自动化系统期望 Dockerfile 位于 Git 存储库的根目录中。

+   保持一个单独的脚本（如果需要）用于创建容器镜像。更具体地说，不要将创建容器镜像的过程与代码生成、编译、测试或验证混在一起。这将清晰地区分出您可能需要的开发任务，具体取决于您的语言和框架。这将允许您在自动化流水线中在需要时包含它。

+   在基础镜像中添加额外工具可能非常诱人，以便进行调试、支持新的或额外的诊断工作等。明确和有意识地选择要在镜像中包含的额外工具。我建议最小化额外工具的使用，不仅因为它们会使镜像变得更大，而且通常那些在调试中非常有效的工具也会给黑客提供更容易利用的选项：

+   如果您发现必须在镜像中添加调试工具，请考虑在子目录中创建第二个 Dockerfile，该文件添加到第一个文件中，并且只包含您想要添加的调试工具。如果这样做，我建议您在镜像的名称中添加一个`-debug`以明确表明该镜像已安装额外的工具。

+   构建容器镜像时，要考虑其生产使用，并将其作为默认设置。对于容器来说，这通常表示容器中提供的环境变量的默认值。一般来说，尽量不要在容器镜像中包含单元测试、开发任务等所需的依赖项：

+   在 Node.js 的情况下，使用环境变量`ENV=PROD`，这样`npm`就不会包含开发依赖项，或者使用命令行`npm install —production`明确地将它们剥离。

+   在创建容器后，将整个容器视为只读文件系统。如果您想要有某个地方来写入本地文件，请明确标识该位置并在容器中设置一个卷。

# 发送程序输出

`kubectl logs`（以及 Docker 的等效命令：`docker logs`）默认将`stdout`和`stderr`组合在一起，并将任何显示为日志的内容传递给容器。您可能也有过在代码中创建特定的日志记录功能，将日志写入磁盘上的文件位置的经验。一般来说，将日志写入文件系统位置不鼓励在容器内运行的软件中，因为要将其包含在一般日志记录中意味着必须再次读取它，这会不必要地增加磁盘 I/O。

如果您希望在应用程序中支持聚合日志记录的方法，那么通常希望在容器和/或 Pod 之外定义一些内容来帮助捕获、传输和处理这些日志。

一般来说，如果您编写程序将日志记录到`stdout`和`stderr`，那么运行这些容器的容器和 Kubernetes 通常会帮助您更轻松地访问这些细节。

# 日志

获取有关代码运行情况的最常见方法通常是通过日志。每种语言和开发环境都有自己的模式来公开这些细节，但基本上，它可以简单地通过打印语句发送一行文本到`stdout`，这对于快速和简单的调试无疑是最一致的方法。当您在 Kubernetes 中部署和运行代码时，它可以访问来自每个 Pod 和容器的日志，其中日志在这种情况下是将数据发送到`stdout`和`stderr`。

如果您现有的开发模式将输出写入特定的文件位置，也许您的框架包括在文件增长时旋转这些日志文件的功能，您可能希望考虑只是将数据发送到`stdout`和/或`stderr`，以便 Kubernetes 可以使这种协调工作。

# 具有多个容器的 Pod

到目前为止，我们的示例都很简单，一个 Pod 中只有一个容器。一个 Pod 可以同时拥有多个容器，获取日志的命令可以指定使用哪个容器。如果只有一个容器，就不需要指定要使用哪个容器。

如果需要指定特定的容器，可以使用`-c`选项，或者将其添加到`logs`命令中。例如，如果有一个名为`webapp`的 Pod，其中包含两个容器`flask`和`background`，你想要查看`background`容器的日志，可以使用`kubectl logs webapp background`或`kubectl logs webapp -c background`命令。

同样，定义部署中的 Pod 和容器也有一个快捷方式。与其通过 Kubernetes 分配的名称来指定完整的 Pod 名称，你可以只用部署名称作为 Pod 名称的前缀。例如，如果我们之前使用`kubectl run flask image=…`命令创建了一个部署，我们可以使用以下命令：

```
kubectl logs deployment/flask
```

这样就不需要查找特定的 Pod 名称，然后根据该名称请求日志了。

# 流式传输日志

通常希望能够连续查看容器的日志，随着容器提供信息而更新。你可以使用`-f`选项来实现这一点。例如，要查看与`flask`部署相关的 Pod 的更新日志，可以运行以下命令：

```
kubectl logs deployment/flask -f
```

当你与该服务交互，或者该服务写入`stdout`并进行正常日志记录时，你会看到输出流到你的控制台。

# 之前的日志

日志通常是特定于活动容器的。然而，通常需要查看如果容器失败时日志中可能包含的内容，或者如果你部署更新后出现了意外情况。Kubernetes 会保留对任何 Pod 的先前容器的引用（如果存在），这样你在需要时就可以获取这些信息。只要日志对 Kubernetes 可用，你可以使用`-p`选项来实现这一点。

# 时间戳

日志输出也可以包含时间戳，尽管默认情况下不会。你可以通过添加`--timestamps`选项来获取带有时间戳前缀的日志消息。例如：

```
kubectl logs deployment/flask --timestamps
```

然后你可能会看到以下内容：

```
2017-09-16T03:54:20.851827407Z  * Running on http://0.0.0.0:5000/ (Press CTRL+C to quit)
2017-09-16T03:54:20.852424207Z  * Restarting with stat
2017-09-16T03:54:21.163624707Z  * Debugger is active!
2017-09-16T03:54:21.165358607Z  * Debugger PIN: 996-805-904
```

值得注意的是，时间戳来自运行容器的主机，而不是您的本地机器，因此这些日志中的时区通常不是您所在的时区。所有时间戳都包括完整的时区细节（通常设置为 UTC-0 时区），因此值可以很容易地转换。

# 更多的调试技术

有几种调试技术可以处理部署到现有集群中的代码。这些包括：

+   容器镜像的交互式部署

+   附加到运行中的 Pod

+   在现有 Pod 中运行第二个命令

# 镜像的交互式部署

您还可以使用 `kubectl run` 命令启动与 Pod 的交互会话。这对于登录并查看容器镜像中可用的内容，或者在您复制到容器镜像中的软件的上下文中非常有用。

例如，如果您想运行一个 shell 来查看我用于 Python 示例的基本 Alpine 容器镜像内部，您可以运行以下命令：

```
kubectl run -i -t alpine-interactive --image=alpine -- sh
```

-i` 选项是告诉它使会话交互，并且 `-t` 选项（几乎总是与 `-i` 选项一起使用）表示它应为交互式输出分配一个 TTY 会话（终端会话）。结尾的 `-- sh` 是一个覆盖，提供一个特定的命令来调用这个会话，在这种情况下是 `sh`，要求执行 shell。

当您调用此命令时，它仍然设置一个部署，当您退出交互式 shell 时，输出将告诉您如何重新连接到相同的交互式 shell。输出将看起来像下面这样：

```
Session ended, resume using 'kubectl attach alpine-interactive-1535083360-4nxj8 -c alpine-interactive -i -t' command when the pod is running
```

如果您想要终止该部署，您需要运行以下命令：

```
kubectl delete deployment alpine-interactive
```

这种技术对于在 Kubernetes 集群中启动和运行容器镜像，并让您与之交互的 shell 访问非常有用。如果您习惯使用 Python、Node.js 或类似的动态语言，那么能够加载所有库并激活 REPL 以便与之交互或交互式地查看运行环境，将会非常有用。

例如，我们可以使用相同的 Python 镜像来为我们的 Flask 应用程序做这个。要将其作为一个可以稍后删除的交互式会话启动，使用以下命令：

```
kubectl run -i -t python-interactive --image=quay.io/kubernetes-for-developers/flask:latest --command -- /bin/sh 
```

此命令可能需要一些时间才能完成，因为它将等待 Kubernetes 下载映像并启动它，使用我们最初放置的命令(`/bin/sh`)，而不是我们为其定义的入口点。不久之后，您应该在终端窗口中看到类似以下的一些输出：

```
If you don't see a command prompt, try pressing enter.
/ #
```

在这一点上，您可以调用 Python 并直接与 Python REPL 交互，加载代码并执行所需的操作。以下是一些示例命令，以显示这可能如何工作：

```
cd /opt/exampleapp
/opt/exampleapp # python3
Python 3.6.1 (default, May 2 2017, 15:16:41)
[GCC 6.3.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import os
>>> os.environ
environ({'KUBERNETES_PORT': 'tcp://10.0.0.1:443', 'KUBERNETES_SERVICE_PORT': '443', 'HOSTNAME': 'python-interactive-666665880-hwvvp', 'SHLVL': '1', 'OLDPWD': '/', 'HOME': '/root', 'TERM': 'xterm', 'KUBERNETES_PORT_443_TCP_ADDR': '10.0.0.1', 'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', 'KUBERNETES_PORT_443_TCP_PORT': '443', 'KUBERNETES_PORT_443_TCP_PROTO': 'tcp', 'KUBERNETES_PORT_443_TCP': 'tcp://10.0.0.1:443', 'KUBERNETES_SERVICE_PORT_HTTPS': '443', 'PWD': '/opt/exampleapp', 'KUBERNETES_SERVICE_HOST': '10.0.0.1'})
>>> import flask
>>> help(flask.app)
Help on module flask.app in flask:
NAME
 flask.app
DESCRIPTION
 flask.app
 ~~~~~~~~~
This module implements the central WSGI application object.
:copyright: (c) 2015 by Armin Ronacher.
 :license: BSD, see LICENSE for more details.
CLASSES
 flask.helpers._PackageBoundObject(builtins.object)
 Flask
class Flask(flask.helpers._PackageBoundObject)
 | The flask object implements a WSGI application and acts as the central
 | object. It is passed the name of the module or package of the
 | application. Once it is created it will act as a central registry for
 | the view functions, the URL rules, template configuration and much more.
 |
 | The name of the package is used to resolve resources from inside the
 | package or the folder the module is contained in depending on if the
 | package parameter resolves to an actual python package (a folder with
>>> exit()
/opt/exampleapp #
```

与部署交互完成后，您可以通过按下*Ctrl* + *D*或输入`exit`来退出 shell。

```
Session ended, resume using 'kubectl attach python-interactive-666665880-hwvvp -c python-interactive -i -t' command when the pod is running
```

这将保持部署运行，因此您可以使用上述命令重新附加到它，或者在需要时删除部署并重新创建它。要删除它，您将使用以下命令：

```
kubectl delete deployment python-interactive
deployment "python-interactive" deleted
```

# 连接到正在运行的 Pod

如果您的 Pod 正在运行，并且您想从该容器映像的上下文中运行一些命令，您可以附加一个交互式会话。您可以通过`kubectl attach`命令来执行此操作。Pod 必须处于活动状态才能使用此命令，因此如果您试图弄清楚为什么 Pod 未正确启动，此命令可能不会有帮助。

附加到 Pod 将连接`stdin`到您的进程，并将`stdout`和`stderr`的任何内容呈现在屏幕上，因此它更像是`kubectl logs -f`命令的交互版本。为了使其有用，您指定的容器还需要接受`stdin`。您还需要显式启用 TTY 才能连接到它。如果不这样做，您经常会看到以下内容作为输出的第一行：

```
Unable to use a TTY - container flask did not allocate one
```

如果您之前使用以下命令从`nodejs`示例创建了一个部署：

```
kubectl run nodejs --image=quay.io/kubernetes-for-developers/nodejs:latest —-port=3000
```

您可以使用以下命令附加到此 Pod：

```
kubectl attach deployment/express -i -t
```

这将返回一个警告消息：

```
Unable to use a TTY - container flask did not allocate one
If you don't see a command prompt, try pressing enter.
```

此后，当您与服务交互时，您将在终端窗口中看到`stdout`流。

如果您的应用程序将其日志打印到`stdout`并且您希望在与代码交互时观看这些日志，例如使用 Web 浏览器，这将非常有效。要使用 Web 浏览器与正在运行的 Pod 进行交互，请记住使用`kubectl proxy`或`kubectl port-forward`命令，通常从另一个终端窗口，将访问从您的笔记本电脑路由到集群中的 Pod。

在许多情况下，您最好使用我们之前描述的带有`-f`选项的`kubectl logs`命令。主要区别在于，如果您已经启用了应用程序以对来自`stdin`的输入做出反应，并且使用了定义了`stdin`和 TTY 的命令运行它，那么您可以直接使用`kubectl attach`命令与其交互。

# 在容器中运行第二个进程

我经常发现在 Pod 中运行额外的命令比尝试附加到 Pod 更有用。您可以使用`kubectl exec`命令来实现这一点。

截至 Kubernetes 1.8，`kubectl exec`不支持我们用于日志或附加命令的部署/名称快捷方式，因此您需要指定要与之交互的特定 Pod 名称。如果您只想在 Pod 中打开交互式 shell，可以运行以下命令：

```
kubectl get pods
NAME                   READY STATUS  RESTARTS AGE
flask-1908233635-d6stj 1/1   Running 0        1m
```

使用运行中的 Pod 的名称，调用`kubectl exec`在其中打开交互式 shell：

```
kubectl exec flask-1908233635-d6stj -it -- /bin/sh # ps aux
PID USER TIME COMMAND
 1 root 0:00 python3 /opt/exampleapp/exampleapp.py
 12 root 0:00 /bin/sh
 17 root 0:00 ps aux
```

您还可以使用此功能调用内置于容器中的任何命令。例如，如果您有一个收集和导出诊断数据的脚本或进程，您可以调用该命令。或者，您可以使用`killall -HUP python3`这样的命令，它将向所有正在运行的`python3`进程发送`HUP`信号。

# Kubernetes 概念-标签

在第一个示例中，您看到创建部署还创建了一个 ReplicaSet 和相关的 Pod，以便运行您的软件。

Kubernetes 具有非常灵活的机制，用于连接和引用其管理的对象。 Kubernetes 项目使用资源上的一组标签，称为标签，而不是具有非常严格的可以连接的层次结构。有一个匹配机制来查询和找到相关的标签，称为选择器。

标签在格式上相当严格定义，并且旨在将 Kubernetes 中的资源分组在一起。它们不打算标识单个或唯一的资源。它们可用于描述一组 Kubernetes 资源的相关信息，无论是 Pod、ReplicaSet、Deployment 等。

正如我们之前提到的，标签是键-值结构。标签中的键大小受限，并且可能包括一个可选的前缀，后跟一个/字符，然后是键的其余部分。如果提供了前缀，则预期使用 DNS 域。Kubernetes 的内部组件和插件预期使用前缀来分组和隔离它们的标签，前缀`kubernetes.io`保留用于 Kubernetes 内部标签。如果未定义前缀，则被认为完全由用户控制，并且你需要维护自己关于非前缀标签意义一致性的规则。

如果你想使用前缀，它需要少于 253 个字符。前缀之外的键的最大长度为 63 个字符。键也只能由字母数字字符、`-`、`_`和`.`指定。Unicode 和非字母数字字符不支持作为标签。

标签旨在表示关于资源的语义信息，拥有多个标签不仅可以接受，而且是预期的。你会看到标签在 Kubernetes 示例中被广泛使用，用于各种目的。最常见的是感兴趣的维度，例如：

+   环境

+   版本

+   应用程序名称

+   服务层级

它们也可以用来跟踪你感兴趣的任何基于你的组织或开发需求的分组。团队、责任领域或其他语义属性都是相当常见的。

# 标签的组织

当你拥有超过“只是一点点”的资源时，对资源进行分组对于维护对系统的理解至关重要，同时也让你能够根据其责任而不是个体名称或 ID 来思考资源。

你应该考虑创建并维护一个包含你使用的标签及其含义和意图的实时文档。我更喜欢在部署目录中的`README.md`中进行这项工作，我会在那里保存 Kubernetes 声明，我发现你设置的任何约定都对理解至关重要，特别是当你作为团队的一部分工作时。即使你是独自工作，这也是一个很好的实践：今天对你来说很明显的东西，也许在六个月甚至更长时间内对*未来的你*来说完全晦涩难懂。

您还有责任清楚地了解自己标签的含义。Kubernetes 不会阻止您混淆或重复使用简单的标签。我们将在本章后面讨论的一种资源称为服务，专门使用标签来协调对 Pods 的访问，因此保持清晰地使用这些标签非常重要。在不同的 Pods 之间重用标签键可能会导致非常意外的结果。

# Kubernetes 概念-选择器

在 Kubernetes 中，选择器用于基于它们具有（或不具有）的标签将资源连接在一起。选择器旨在提供一种在 Kubernetes 中检索一组资源的方法。

大多数`kubectl`命令支持`-l`选项，允许您提供选择器以过滤其查找的内容。

选择器可以基于相等性表示特定值，也可以基于集合表示允许基于多个值进行过滤和选择。相等选择器使用`=`或`!=`。集合选择器使用`in`，`notin`和`exists`。您可以将这些组合在一个选择器中，通过在它们之间添加`,`来创建更复杂的过滤器和选择条件。

例如，您可以使用标签`app`来表示提供特定应用程序服务的 Pods 分组-在这种情况下，使用值`flask`和`tier`来表示`front-end`，`cache`和`back-end`层的值。可能返回与该应用相关的所有资源的选择器可能是：

```
app=flask
```

并且刚刚返回支持此应用程序的前端资源的选择器：

```
app=flask,tier in (front-end)
```

如果您想列出所有与选择`app=flask`匹配的 Pods，您可以使用以下命令：

```
kubectl get pods -l app=flask
```

# 查看标签

我们之前通过`kubectl run`命令创建的部署放置了标签并将它们用作选择器。正如您之前看到的，您可以使用`kubectl get -o json`命令获取 Kubernetes 资源的所有底层详细信息。

类似的命令是`kubectl describe`，旨在提供资源及其最近历史的人类可读概述：

```
kubectl describe deployment flask
```

这将提供类似以下的输出：

```
Name: flask
Namespace: default
CreationTimestamp: Sat, 16 Sep 2017 08:31:00 -0700
Labels: pod-template-hash=866287979
 run=flask
Annotations: deployment.kubernetes.io/revision=1
kubectl.kubernetes.io/last-applied-configuration={"apiVersion":"apps/v1beta1","kind":"Deployment","metadata":{"annotations":{},"labels":{"run":"flask"},"name":"flask","namespace":"default"},"spec":{"t...
Selector: app=flask
Replicas: 1 desired | 1 updated | 1 total | 1 available | 0 unavailable
StrategyType: RollingUpdate
MinReadySeconds: 0
RollingUpdateStrategy: 25% max unavailable, 25% max surge
Pod Template:
 Labels: app=flask
 Containers:
 flask:
 Image: quay.io/kubernetes-for-developers/flask:latest
 Port: 5000/TCP
 Environment: <none>
 Mounts: <none>
 Volumes: <none>
Conditions:
 Type Status Reason
 ---- ------ ------
 Available True MinimumReplicasAvailable
 Progressing True NewReplicaSetAvailable
OldReplicaSets: <none>
NewReplicaSet: flask-866287979 (1/1 replicas created)
Events:
 FirstSeen LastSeen Count From SubObjectPath Type Reason Message
 --------- -------- ----- ---- ------------- -------- ------ -------
 2d 2d 1 deployment-controller Normal ScalingReplicaSet Scaled up replica set flask-866287979 to 1
```

您会注意到其中有两个标签，`run`和`pod-template-hash`，以及一个选择器，`app=flask`。例如，您可以使用`kubectl get`命令行查询这些确切的标签：

```
kubectl get deployment -l run=flask
```

这将返回匹配该选择器的部署：

```
NAME      DESIRED   CURRENT   UP-TO-DATE   AVAILABLE   AGE
flask     1         1         1            1           2d
```

以及对 Pods 的等效请求选择器

```
kubectl get pods -l app=flask
```

这将返回匹配`app=flask`选择器的 Pods：

```
NAME                    READY     STATUS    RESTARTS   AGE
flask-866287979-bqg5w   1/1       Running   0          2d
```

在这个部署中，Pod 是使用选择器`app=flask`从部署中引用的。

**注意**：您可以与`kubectl get`一起使用选择器来一次请求多种资源。例如，如果您使用`app=flask`标记了所有相关资源，那么您可以使用诸如`kubectl get deployment,pod -l app=flask`的命令来查看部署和 Pod。

正如您所看到的，当您交互式地创建和运行资源时，通常会隐式使用一些常见的标签结构。`kubectl run`创建部署时，使用`run`、`pod-template-hash`和`app`键具有特定的含义。

标签也可以在资源已经存在后，使用`kubectl label`命令进行交互式应用。例如，要为 Pod 应用一个名为 enabled 的标签，您可以使用以下命令：

```
kubectl label pods your-pod-name enable=true
```

这使您可以交互式地将资源分组在一起，或者提供一种一致的方式来推出、更新，甚至移除一组资源。

# 使用 kubectl 列出带有标签的资源

`kubectl get`命令默认会显示基本信息，通常是您要查找的资源的名称和状态。您可以扩展它显示的列，以包括特定的标签，这通常可以使在处理大量不同的 Pods、部署和 ReplicaSets 时更容易找到您要查找的内容。`kubectl`使用`-L`选项和逗号分隔的标签键列表作为标题显示。

如果您想显示 Pods 以及标签键`run`和`pod-template-hash`，命令将是：

```
kubectl get pods -L run,pod-template-hash
```

然后您可能会看到以下输出：

```
NAME READY STATUS RESTARTS AGE RUN POD-TEMPLATE-HASH
flask-1908233635-d6stj 1/1 Running 1 20h flask 1908233635
```

# 自动标签和选择器

Kubernetes 包括许多命令，可以自动为您创建许多资源。当这些命令创建资源时，它们还会应用自己的约定标签，并使用这些标签将资源联系在一起。一个完美的例子就是我们现在已经使用了好几次的命令：`kubectl run`。

例如，当我们使用：

```
kubectl run flask --image=quay.io/kubernetes-for-developers/flask:latest
```

这创建了一个名为`flask`的部署。当部署的控制器被创建时，这反过来导致了为该部署创建一个 ReplicaSet，而 ReplicaSet 控制器又创建了一个 Pod。我们之前看到这些资源的名称都是相关的，它们之间也有相关的标签。

部署`flask`是使用`run=flask`标签创建的，使用`kubectl`命令的名称作为键，并且我们在命令行上提供的名称作为值。部署还具有选择器`run=flask`，以便它可以将其控制器规则应用于为其创建的相关 ReplicaSets 和 Pods。

查看创建的 ReplicaSet，您将看到`run=flask`标签以及与使用`pod-template-hash`键为 ReplicaSet 创建的名称相对应的标签。这个 ReplicaSet 还包括相同的选择器来引用为其创建的 Pods。

最后，Pod 具有相同的选择器，这就是当需要时 ReplicaSet 和部署如何知道与 Kubernetes 中的哪些资源进行交互。

以下是总结了前面示例中自动创建的标签和选择器的表格：

|  | 部署 | ReplicaSet | Pod |
| --- | --- | --- | --- |
| 名称 | `flask` | `flask-1908233635` | `flask-1908233635-d6stj` |
| 标签 | `run=flask` | `pod-template-hash=1908233635` `run=flask` | `pod-template-hash=1908233635` `run=flask` |
| 选择器 | `run=flask` | `pod-template-hash=1908233635,run=flask` |  |

# Kubernetes 资源 - 服务

到目前为止，我们探讨的所有细节都与在 Kubernetes 中运行的单个容器相关。当一起运行多个容器时，利用 Kubernetes 的重大好处开始发挥作用。能够将一组做同样事情的 Pods 组合在一起，以便我们可以对它们进行扩展和访问，这就是 Kubernetes 资源服务的全部内容。

服务是 Kubernetes 资源，用于提供对 Pod（或 Pods）的抽象，不考虑正在运行的特定实例。在一个容器（或一组容器）提供的内容与另一层，比如数据库之间提供一个层，允许 Kubernetes 独立扩展它们，更新它们，处理扩展问题等。服务还可以包含数据传输的策略，因此您可以将其视为 Kubernetes 中的软件负载均衡器。

服务也是用于将 Pod 公开给彼此或将容器公开给 Kubernetes 集群外部的关键抽象。服务是 Kubernetes 管理 Pod 组之间以及进出它们的流量的核心。

服务的高级用法还允许您为集群之外的资源定义服务。这可以让您以一致的方式使用服务，无论您需要运行的端点是来自 Kubernetes 内部还是集群外部。

Kubernetes 包括一个`expose`命令，可以基于集群内已经运行的资源创建服务。例如，我们可以使用以下命令暴露我们之前使用的`flask`部署示例：

```
kubectl expose deploy flask --port 5000
service "flask" exposed
```

大多数服务将定义一个 ClusterIP，Kubernetes 将处理所有动态链接资源的工作，当匹配相关选择器的 Pod 被创建和销毁时。您可以将其视为 Kubernetes 内部的简单负载均衡器构造，并且它将在 Pod 可用时内部转发流量，并停止向失败或不可用的 Pod 发送流量。

如果您使用`expose`命令请求我们刚刚创建的服务的详细信息，您将看到列出了 ClusterIP：

```
kubectl get service flask
```

```

NAME TYPE CLUSTER-IP EXTERNAL-IP PORT(S) AGE
flask ClusterIP 10.0.0.168 <none> 5000/TCP 20h
```

# 定义服务资源

服务规范在版本 1.8 的文档中非常简单，可以在[`kubernetes.io/docs/api-reference/v1.8/#service-v1-core`](https://kubernetes.io/docs/api-reference/v1.8/#service-v1-core)找到。Kubernetes 中的所有资源都可以以声明方式定义，我们将在第四章“声明式基础设施”中更深入地研究这一点。资源也可以使用 YAML 和 JSON 来定义。为了查看可以包含在服务资源中的细节，我们将查看其 YAML 规范。规范的核心包括名称、为提供服务的 Pod 选择器以及与服务相关的端口。

例如，我们的`flask` Pod 的简单服务声明可能是：

```
kind: Service
apiVersion: v1
metadata:
 name: service
spec:
 selector:
 run: flask
 ports:
 - protocol: TCP
 port: 80
    targetPort: 5000
```

这定义了一个服务，使用选择器`run: flask`选择要前置的 Pod，并在 TCP 端口`80`上接受任何请求，并将其转发到所选 Pod 的端口`5000`。服务支持 TCP 和 UDP。默认是 TCP，所以我们严格来说不需要包含它。此外，targetPort 可以是一个字符串，指的是端口的名称，而不仅仅是端口号，这允许服务之间具有更大的灵活性，并且可以根据开发团队的需求移动特定的后端端口，而无需进行太多的仔细协调以保持整个系统的运行。

服务可以定义（和重定向）多个端口 - 例如，如果您想要支持端口`80`和`443`的访问，可以在服务上定义它。

# 端点

服务不需要选择器，没有选择器的服务是 Kubernetes 用来表示集群外部服务的方式。为了实现这一点，您创建一个没有选择器的服务，以及一个新的资源，即端点，它定义了远程服务的网络位置。

如果您正在将服务迁移到 Kubernetes，并且其中一些服务是集群外部的，这提供了一种将远程系统表示为内部服务的方式，如果以后将其移入 Kubernetes，则无需更改内部 Pod 连接或利用该资源的方式。这是服务的高级功能，也不考虑授权。另一个选择是不将外部服务表示为服务资源，而是在 Secrets 中简单地引用它们，这是我们将在下一章中更深入地研究的功能。

例如，如果您在互联网上以 IP 地址`1.2.3.4`的端口`1976`上运行远程 TCP 服务，则可以定义一个服务和端点来引用`Kubernetes 外部`系统：

```
kind: Service
apiVersion: v1
metadata:
 name: some-remote-service
spec:
 ports:
 - protocol: TCP
 port: 1976
 targetPort: 1976
```

这将与以下`Endpoints`定义一起工作：

```
kind: Endpoints
apiVersion: v1
metadata:
 name: some-remote-service
subsets:
 - addresses:
 - ip: 1.2.3.4
 ports:
 - port: 1976
```

# 服务类型 - ExternalName

前面的 Endpoint 定义有一个变体，它只提供 DNS 引用，称为`ExternalName`服务。像`Endpoint`定向服务一样，它不包括选择器，但也不包括任何端口引用。相反，它只定义了一个外部 DNS 条目，可以用作服务定义。

以下示例为 Kubernetes 内部提供了一个服务接口，用于外部 DNS 条目`my.rest.api.example.com`：

```
kind: Service
apiVersion: v1
metadata:
 name: another-remote-service
 namespace: default
spec:
 type: ExternalName
 externalName: my.rest.api.example.com
```

与其他服务不同，其他服务提供 TCP 和 UDP（ISO 网络堆栈上的第 4 层）转发，`ExternalName`只提供 DNS 响应，不管理任何端口转发或重定向。

# 无头服务

如果有理由要明确控制您连接和通信的特定 Pod，可以创建一个不分配 IP 地址或转发流量的服务分组。这种服务称为无头服务。您可以通过在服务定义中明确设置 ClusterIP 为`None`来请求此设置：

例如，无头服务可能是：

```
kind: Service
apiVersion: v1
metadata:
 name: flask-service
spec:
 ClusterIP: None
 selector:
 app: flask
```

对于这些服务，将创建指向支持服务的 Pod 的 DNS 条目，并且该 DNS 将在与选择器匹配的 Pod 上线（或消失）时自动更新。

**注意**：要注意 DNS 缓存可能会妨碍无头服务的使用。在建立连接之前，您应该始终检查 DNS 记录。

# 从 Pod 内部发现服务

有两种方式可以从 Pod 内部看到服务。第一种是通过环境变量添加到与服务相同命名空间中的所有 Pod。

当您添加服务（使用`kubectl create`或`kubectl apply`）时，该服务将在 Kubernetes 中注册，此后启动的任何 Pod 都将设置引用该服务的环境变量。例如，如果我们创建了前面的第一个示例服务，然后运行：

```
kubectl get services
```

我们会看到列出的服务：

```
NAME            CLUSTER-IP   EXTERNAL-IP   PORT(S)   AGE
flask           10.0.0.61    <none>        80/TCP    2d
kubernetes      10.0.0.1     <none>        443/TCP   5d
```

如果您查看容器内部，您会看到与先前列出的两个服务相关联的环境变量。这些环境变量是：

```
env
```

```
KUBERNETES_PORT=tcp://10.0.0.1:443
KUBERNETES_SERVICE_PORT=443
KUBERNETES_PORT_443_TCP_ADDR=10.0.0.1
KUBERNETES_PORT_443_TCP_PORT=443
KUBERNETES_PORT_443_TCP_PROTO=tcp
KUBERNETES_PORT_443_TCP=tcp://10.0.0.1:443
KUBERNETES_SERVICE_PORT_HTTPS=443
KUBERNETES_SERVICE_HOST=10.0.0.1
FLASK_SERVICE_PORT_80_TCP_ADDR=10.0.0.61
FLASK_SERVICE_PORT_80_TCP_PORT=80
FLASK_SERVICE_PORT_80_TCP_PROTO=tcp
FLASK_SERVICE_PORT_80_TCP=tcp://10.0.0.61:80
FLASK_SERVICE_SERVICE_HOST=10.0.0.61
FLASK_SERVICE_SERVICE_PORT=80
FLASK_SERVICE_PORT=tcp://10.0.0.61:80
```

（前面的输出已经重新排序，以便更容易看到值，并删除了一些多余的环境变量。）

对于每个服务，都定义了环境变量，提供了 IP 地址、端口和协议，还有一些名称变体。请注意，这个 IP 地址不是任何底层 Pod 的 IP 地址，而是 Kubernetes 集群中的 IP 地址，服务将其作为访问所选 Pod 的单个端点进行管理。

**警告**：服务的顺序很重要！如果 Pod 在定义服务之前存在，那么该服务的环境变量将不会存在于这些 Pod 中。重新启动 Pods，或将其缩减到`0`然后再次启动（强制容器被杀死和重新创建）将解决此问题，但通常最好始终首先定义和应用您的服务声明。

# 服务的 DNS

最初并不是核心分发的一部分，现在在 1.3 版（以及更高版本）的所有集群中都包含了一个集群附加组件，为 Kubernetes 提供了内部 DNS 服务。例如，Minikube 包括了这个附加组件，并且很可能已经在您的集群中运行。

将创建一个 DNS 条目，并与定义的每个服务协调，以便您可以请求`<service>`或`<service>.<namespace>`的 DNS 条目，并且内部 DNS 服务将为您提供正确的内部 IP 地址。

例如，如果我们使用`expose`命令公开`flask`部署，该服务将在我们的容器中列出 DNS。我们可以打开一个交互式终端到现有的 Pod，并检查 DNS：

```
kubectl exec flask-1908233635-d6stj -it -- /bin/sh
```

```
/ # nslookup flask
nslookup: can't resolve '(null)': Name does not resolve
Name: flask
Address 1: 10.0.0.168 flask.default.svc.cluster.local
```

每个服务在 DNS 中都会获得一个内部 A 记录（地址记录）`<servicename>.<namespace>.svc.cluster.local`，作为快捷方式，它们通常可以在 Pods 中被引用为`<servicename>.<namespace>.svc`，或者更简单地为所有在同一命名空间中的 Pods 的`<servicename>`。

**注意**：只有在您明确尝试引用另一个命名空间中的服务时，才应该添加命名空间。不带命名空间会使您的清单本质上更具重用性，因为您可以将整个服务堆栈与静态路由配置放入任意命名空间。

# 在集群外部公开服务

到目前为止，我们讨论的一切都是关于在 Kubernetes 集群内部表示服务。服务概念也是将应用程序暴露在集群外部的方式。

默认服务类型是 ClusterIP，我们简要介绍了类型`ExternalName`，它是在 Kubernetes 1.7 中添加的，用于提供外部 DNS 引用。还有另外两种非常常见的类型，`NodePort`和`LoadBalancer`，它们专门用于在 Kubernetes 集群之外公开服务。

# 服务类型 - LoadBalancer

`LoadBalancer`服务类型在所有 Kubernetes 集群中都不受支持。它最常用于云提供商，如亚马逊、谷歌或微软，并与云提供商的基础设施协调，以设置一个外部`LoadBalancer`，将流量转发到服务中。

定义这些服务的方式是特定于您的云提供商的，并且在 AWS、Azure 和 Google 之间略有不同。 `LoadBalancer`服务定义还可能包括推荐的注释，以帮助定义如何处理和处理 SSL 流量。有关每个提供程序的具体信息，可以在 Kubernetes 文档中找到。有关 LoadBalancer 定义的文档可在[`kubernetes.io/docs/concepts/services-networking/service/#type-loadbalancer`](https://kubernetes.io/docs/concepts/services-networking/service/#type-loadbalancer)上找到。

# 服务类型 - NodePort

当您在本地使用 Kubernetes 集群，或者在我们的情况下，在 Minikube 上的虚拟机上使用开发机器时，NodePort 是一种常用的服务类型，用于暴露您的服务。NodePort 依赖于运行 Kubernetes 的基础主机在您的本地网络上可访问，并通过所有 Kubernetes 集群节点上的高端口公开服务定义。

这些服务与默认的 ClusterIP 服务完全相同，唯一的区别是它们的类型是`NodePort`。如果我们想要使用`expose`命令创建这样一个服务，我们可以在之前的命令中添加一个`--type=Nodeport`选项，例如：

```
kubectl delete service flask
```

```
kubectl expose deploy flask --port 5000 --type=NodePort
```

这将导致一个定义看起来像以下的东西：

```
kubectl get service flask -o yaml

apiVersion: v1
kind: Service
metadata:
 creationTimestamp: 2017-10-14T18:19:07Z
 labels:
 run: flask
 name: flask
 namespace: default
 resourceVersion: "19788"
 selfLink: /api/v1/namespaces/default/services/flask
 uid: 2afdd3aa-b10c-11e7-b586-080027768e7d
spec:
 clusterIP: 10.0.0.39
 externalTrafficPolicy: Cluster
 ports:
 - nodePort: 31501
 port: 5000
 protocol: TCP
 targetPort: 5000
 selector:
 run: flask
 sessionAffinity: None
 type: NodePort
status:
 loadBalancer: {}
```

注意`nodePort: 31501`。这是服务暴露的端口。启用了这个选项后，以前我们必须使用端口转发或代理来访问我们的服务，现在可以直接通过服务来做。

# Minikube 服务

Minikube 有一个服务命令，可以非常容易地获取和访问这个服务。虽然您可以使用`minikube ip`获取您的`minikube`主机的 IP 地址，并将其与先前的端口组合在一起，但您也可以使用`minikube service`命令在一个命令中创建一个组合的 URL：

```
minikube service flask --url
```

这应该返回一个像这样的值：

```
http://192.168.64.100:31505
```

而且`minikube`有一个有用的选项，如果你使用以下命令，可以打开一个浏览器窗口：

```
minikube service flask
```

```
Opening kubernetes service default/flask in default browser...
```

如果您启用了一个服务，但没有 Pod 支持该服务，那么您将看到一个连接被拒绝的消息。

您可以使用以下命令列出从您的`minikube`实例暴露的所有服务：

```
minikube service list
```

然后您将看到类似以下的输出：

```
|-------------|----------------------|-----------------------------|
| NAMESPACE   |       NAME           |           URL               |
|-------------|----------------------|-----------------------------|
| default     | flask                | http://192.168.99.100:31501 |
| default     | kubernetes           | No node port                |
| kube-system | kube-dns             | No node port                |
| kube-system | kubernetes-dashboard | http://192.168.99.100:30000 |
|-------------|----------------------|-----------------------------|
```

# 示例服务 - Redis

我们将在 Kubernetes 中创建一个示例服务，向您展示如何连接服务，并使用它们来设计您的代码。Redis（[`redis.io`](https://redis.io)）是一个超级灵活的数据存储，您可能已经很熟悉了，它很容易从 Python 和 Node.js 中使用。

Redis 已经作为一个容器可用，并且很容易在 Docker Hub（[`hub.docker.com/`](https://hub.docker.com/)）上找到作为一个容器镜像。有几个选项可用，相关标签在 Docker Hub 网页上列出：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-dev/img/d602d47e-f217-49d7-adeb-cd47a22afea8.png)

我们可以使用`kubectl run`命令使用这个镜像创建一个部署，然后使用`kubectl expose`命令创建一个服务来映射到部署中的 Pod：

```
kubectl run redis --image=docker.io/redis:alpine
```

我们将创建一个名为`redis`的部署，并通过该部署下载镜像并开始运行它。我们可以看到 Pod 正在运行：

```
kubectl get pods
```

```
NAME                     READY     STATUS    RESTARTS   AGE
flask-1908233635-d6stj   1/1       Running   1          1d
redis-438047616-3c9kt    1/1       Running   0          21s
```

您可以使用`kubectl exec`命令在此 Pod 中运行交互式 shell，并直接查询运行中的`redis`实例：

```
kubectl exec -it redis-438047616-3c9kt -- /bin/sh
```

```
/data # ps aux
PID   USER     TIME   COMMAND
    1 redis      0:22 redis-server
   24 root       0:00 /bin/sh
   32 root       0:00 ps aux
/data # which redis-server
/usr/local/bin/redis-server
/data # /usr/local/bin/redis-server --version
Redis server v=4.0.2 sha=00000000:0 malloc=jemalloc-4.0.3 bits=64
build=7f502971648182f2
/data # exit
```

我们可以使用`NodePort`在我们的集群实例内部和`minikube`外部暴露这个服务。`redis`的默认端口是`6379`，所以我们需要确保在我们的服务中包含这个端口：

```
kubectl expose deploy redis --port=6379 --type=NodePort
```

```
service "redis" exposed
```

如果我们列出可用的服务：

```
kubectl get services
```

```
NAME         TYPE        CLUSTER-IP   EXTERNAL-IP   PORT(S)          AGE
flask        NodePort    10.0.0.39    <none>        5000:31501/TCP   3h
kubernetes   ClusterIP   10.0.0.1     <none>        443/TCP          1d
redis        NodePort    10.0.0.119   <none>        6379:30336/TCP   15s
```

我们将看到`redis`在端口`30336`上使用`NodePort`暴露。`minikube service`命令在这里不会立即有帮助，因为 redis 不是基于 HTTP 的 API，但是使用`minikube ip`，我们可以组合一个命令来通过其命令行界面与`redis`交互：

```
minikube ip
```

```
**192.168.99.100** 
```

要与`redis`交互，我们可以使用`redis-cli`命令行工具。如果您没有这个工具，您可以从[`redis.io/download`](https://redis.io/download)下载并按照本例进行操作：

```
redis-cli -h 192.168.99.100 -p 30336
```

```
192.168.99.100:30336>
192.168.99.100:30336> ping
PONG  
```

# 查找 Redis 服务

有了 Redis 服务正在运行，我们现在可以从我们自己的 Pod 中使用它。正如我们之前提到的，有两种方法可以定位服务：基于服务名称的环境变量将设置为主机 IP 和端口，或者您可以使用基于服务名称的 DNS 条目。

环境变量只会在服务之后创建的 Pod 上设置。如果您仍然像我们之前的示例那样运行`flask` Pod，那么它将不会显示环境变量。如果我们创建一个新的 Pod，甚至是一个临时的 Pod，那么它将包括环境变量中的服务。这是因为环境变量是根据 Pod 创建时的 Kubernetes 状态设置的，并且在 Pod 的生命周期内不会更新。

然而，DNS 会根据集群的状态动态更新。虽然不是即时的，但这意味着在服务创建后，DNS 请求将开始返回预期的结果。而且因为 DNS 条目是根据命名空间和服务名称可预测的，它们可以很容易地包含在配置数据中。

**注意：**使用 DNS 进行服务发现，而不是环境变量，因为 DNS 会随着您的环境更新，但环境变量不会。

如果您仍在运行 Flask 或 Node.js Pod，请获取 Pod 名称并在其中打开一个 shell：

```
kubectl get pods
```

```
NAME                     READY     STATUS    RESTARTS   AGE
flask-1908233635-d6stj   1/1       Running   1          2d
redis-438047616-3c9kt    1/1       Running   0          1d
```

```
kubectl exec flask-1908233635-d6stj -it -- sh 
```

然后，我们可以查找我们刚刚在默认命名空间中创建的 Redis 服务，它应该被列为`redis.default`：

```
/ # nslookup redis.default
nslookup: can't resolve '(null)': Name does not resolve
Name:      redis.default
Address 1: 10.0.0.119 redis.default.svc.cluster.local
```

# 从 Python 中使用 Redis

一旦我们可以访问我们的 Python Pod，我们可以调用 Python 进行交互并访问 Redis。请记住，当我们创建这个 Pod 时，我们没有包含任何用于 Redis 的 Python 库。在这个示例中，我们可以即时安装它们，但这种更改只对这个单独的 Pod 有效，并且只在这个 Pod 的生命周期内有效。如果 Pod 死掉，任何更改（比如添加 Redis 库）都将丢失。

这是一个很好的工具，可以交互式地动态尝试各种操作，但请记住，您需要将任何所需的更改合并到创建容器的过程中。

在`flask` Pod 中，转到我们设置的代码目录，我们可以使用 PIP 添加 Redis 库：

```
# cd /opt/exampleapp/
/opt/exampleapp # pip3 install redis
Collecting redis
  Downloading redis-2.10.6-py2.py3-none-any.whl (64kB)
    100% |████████████████████████████████| 71kB 803kB/s
Installing collected packages: redis
Successfully installed redis-2.10.6
```

现在，我们可以交互式地尝试从 Python 中使用 Redis：

```
/opt/exampleapp # python3
Python 3.6.1 (default, May  2 2017, 15:16:41)
[GCC 6.3.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import redis
>>> redis_db = redis.StrictRedis(host="redis.default", port=6379, db=0)
>>> redis_db.ping()
True
>>> redis_db.set("hello", "world")
True
>>> redis_db.get("hello")
b'world'
```

为了匹配这一点并为我们的 Python 代码启用这个库，我们需要将它添加到 Docker 构建过程中使用的`requirements.txt`文件中，以安装所有依赖项。然后我们需要重新构建容器并将其推送到注册表，然后重新创建 Pods，以便使用新的镜像。

# 更新 Flask 部署

此更新过程的步骤如下：

+   在源代码控制中更新代码或依赖项

+   构建并标记一个新的 Docker 镜像

+   将 Docker 镜像推送到容器存储库

+   更新 Kubernetes 中的部署资源以使用这个新镜像

通过逐步进行这个示例，可以突出显示您可以开始推出代码更新，直接或通过添加其他服务到您的应用程序。

在这个示例中，我们不会立即更改任何代码，我们只是想包含 Redis Python 库，以便它可用。为了做到这一点，我们通常会使用 PIP 来安装我们想要的库。通过我们的 Python 示例，我们通过依赖项列表`requirements.txt`使用 PIP 安装所有所需的库，这在 Docker 构建过程中被调用：

+   更新`requirements.txt`文件以包括 Redis：

```
Flask==0.12.2
redis
```

不指定特定版本是向 PIP 表明您希望它找到最新版本并安装它。如果您已经知道 `redis` 库的版本，或者想要明确地固定它，您可以添加它，比如 `==2.10.6`（类似于之前添加的 Flask）。

+   重新构建 `docker` 镜像：

```
docker build .
Sending build context to Docker daemon  162.8kB
Step 1/9 : FROM alpine
…
Removing intermediate container d3ee8e22a095
Successfully built 63635b37136a
```

在这个例子中，我明确地重新构建了一个没有标签的镜像，打算在第二步中添加标签：

+   给 `build` 打标签

要给一个 `build` 打标签，使用以下命令：

```
docker tag <image_id> <container_repository>/<group_name>/<container_name>:<tag>
```

我在这个例子中使用的命令是：

```
docker tag 63635b37136a quay.io/kubernetes-for-developers/flask:0.1.1 
```

一旦构建的镜像有您想要关联的标签（在本例中，我们使用了 `0.1.1`），您可以为其添加多个值的标签，以便以不同的方式引用该镜像。一旦标记完成，您需要使这些镜像可用于您的集群。

+   推送容器镜像：

```
docker push quay.io/kubernetes-for-developers/flask:0.1.1
```

```
The push refers to a repository [quay.io/kubernetes-for-developers/flask]
34f306a8fb12: Pushed
801c9c3c42e7: Pushed
e94771c57351: Pushed
9c99a7f27402: Pushed
993056b64287: Pushed
439786010e37: Pushed
5bef08742407: Layer already exists
0.1.1: digest: sha256:dc734fc37d927c6074b32de73cd19eb2a279c3932a06235d0a91eb66153110ff size: 5824
```

容器标签不需要以点版本格式。在这种情况下，我选择了一个简单和有上下文的标签，但也是明确的，而不是重复使用 `latest`，这可能会导致对我们正在运行的 `latest` 产生一些混淆。

**注意**：使用有意义的标签，并且在运行 Kubernetes 时避免使用 `latest` 作为标签。如果一开始就使用明确的标签，您将节省大量时间来调试确切运行的版本。甚至像 Git 哈希或非常明确的时间戳都可以用作标签。

现在，我们可以更新部署，指示 Kubernetes 使用我们创建的新镜像。Kubernetes 支持几个命令来实现我们想要的效果，比如 `kubectl replace`，它将采用 YAML 或 JSON 格式的更改规范，您可以更改任何值。还有一个较旧的命令 `kubectl rolling-update`，但它只适用于复制控制器。

**注意**：复制控制器是 ReplicaSet 的早期版本，并已被 ReplicaSets 和 Deployments 所取代。

`kubectl rolling-update` 命令已被 `kubectl set` 和 `kubectl rollout` 命令的组合所取代，这适用于部署以及一些其他资源。`kubectl set` 命令有助于频繁更新一些常见更改，比如更改部署中的镜像、在部署中定义的环境变量等等。

`kubectl apply`命令类似于`kubectl replace`，它接受一个文件（或一组文件）并动态应用到所有引用的 kubernetes 资源的差异。我们将在下一章更深入地研究使用`kubectl apply`命令，我们还将研究如何在声明文件中维护应用程序及其结构的定义，而不是依赖于交互式命令的顺序和调用。

正如你所看到的，有很多选择可以进行; 所有这些都归结为更改在 Kubernetes 中定义的资源，以便让它执行某些操作。

让我们选择最一般的选项，并使用`kubectl replace`命令，逐步进行过程，以清楚地说明我们正在改变什么。

首先，获取我们正在更改的部署：

```
kubectl get deploy flask -o yaml --export > flask_deployment.yaml
```

现在，在文本编辑器中打开`flask_deployment.yaml`文件，并找到指定图像的行。当前图像版本可以在文件中的`template -> spec -> containers`下找到，并应该读取类似以下内容：

```
- image: quay.io/kubernetes-for-developers/flask:latest
```

编辑文件并更改为引用我们更新的标签：

```
- image: quay.io/kubernetes-for-developers/flask:0.1.1
```

现在，我们可以使用`kubectl replace`命令告诉 Kubernetes 更新它：

```
kubectl replace -f flask_deployment.yaml
deployment "flask" replaced
```

此更改将启动与部署相关的资源的更新，这种情况下进行滚动更新或部署。部署控制器将自动为部署创建新的 ReplicaSet 和 Pod，并在可用后终止旧的。在此过程中，该过程还将维护规模或运行的副本数量，并可能需要一些时间。

**注意**：你还应该知道`kubectl edit`命令，它允许你指定一个资源，比如一个部署/flask，并直接编辑它的 YAML 声明。当你保存用`kubectl edit`打开的编辑器窗口时，它会执行之前`kubectl replace`命令的操作。

你可以使用`kubectl get pods`来查看这个过程：

```
kubectl get pods
```

```
NAME                     READY     STATUS              RESTARTS   AGE
flask-1082750864-nf99q   0/1       ContainerCreating   0          27s
flask-1908233635-d6stj   1/1       Terminating         1          2d
redis-438047616-3c9kt    1/1       Running             0          1d
```

由于只有一个具有单个容器的 Pod，完成时间不会太长，完成后你会看到类似以下的内容：

```
kubectl get pods
```

```
NAME                     READY     STATUS    RESTARTS   AGE
flask-1082750864-nf99q   1/1       Running   0          1m
redis-438047616-3c9kt    1/1       Running   0          1d
```

你可能会注意到副本集哈希已经改变，以及 Pod 的唯一标识符。如果我们现在使用交互式会话访问此 Pod，我们可以看到库已加载。这一次，我们将直接使用 Python 的交互式 REPL：

```
kubectl exec flask-1082750864-nf99q -it -- python3
```

```
Python 3.6.1 (default, Oct  2 2017, 20:46:59)
[GCC 6.3.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import redis
>>> redis_db = redis.StrictRedis(host="redis.default", port=6379, db=0)
>>> redis_db.ping()
True
>>> redis_db.get('hello')
b'world'
>>> exit()
```

# 部署和滚动

更改部署中的镜像会启动一个部署。部署的滚动更新是一个异步过程，需要时间来完成，并由部署中定义的值控制。如果您查看我们转储到 YAML 并更新的资源文件，您将看到我们使用`kubectl run`命令创建部署时创建的默认值。

在`spec -> strategy`下，您将看到如何处理更新的默认规范：

```
 strategy:
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 1 **type: RollingUpdate** 
```

截至 Kubernetes 1.8，有两种可用的策略：`Recreate`和`RollingUpdate`。`RollingUpdate`是默认值，旨在用于在进行代码更新时保持服务可用性的主要用例。Recreate 的操作方式不同：在创建新的具有更新版本的 pod 之前，杀死所有现有的 pod，这可能会导致短暂的中断。

`RollingUpdate`由两个值控制：`maxUnavailable`和`maxSurge`，它们提供了一些控制，以便在更新进行时您可以拥有最少数量的可用 pod 来处理您的服务。您可以在[`kubernetes.io/docs/concepts/workloads/controllers/deployment/`](https://kubernetes.io/docs/concepts/workloads/controllers/deployment/)的文档中找到有关这两个控制选项的详细信息，以及一些其他影响部署过程的选项。

# 部署历史

Kubernetes 还维护着一个历史记录（其长度也可以受到控制）用于部署。您可以通过`kubectl rollout`命令查看部署的状态以及其历史记录。

例如，要查看我们刚刚执行的部署状态：

```
kubectl rollout status deployment/flask
```

```
deployment "flask" successfully rolled out
```

您可以使用以下命令查看部署更改的历史记录：

```
kubectl rollout history deployment/flask
```

```
deployments "flask"
REVISION  CHANGE-CAUSE
1         <none>
2         <none>
```

`change-cause`作为部署资源的注释进行跟踪，（截至 Kubernetes 1.8）由于我们使用默认的`kubectl run`命令创建了部署，因此它不存在。有一个`--record=true`选项，可以与`kubectl run`、`kubectl set`和其他一些明确设置这些注释的命令一起使用。我们将在下一章节中详细讨论注释。

我们可以继续创建一个注释，以匹配我们刚刚执行的操作，使用以下命令：

```
kubectl annotate deployment flask kubernetes.io/change-cause='deploying image 0.1.1'
```

```
deployment "flask" annotated
```

现在，如果我们查看历史记录，您将看到以下内容显示：

```
kubectl rollout history deployment/flask
```

```
deployments "flask"
REVISION  CHANGE-CAUSE
1         <none>
2         deploying image 0.1.1
```

您可以使用`history`命令的`--revision`选项获取更详细的信息。例如：

```
kubectl rollout history deployment flask --revision=2
```

这将返回类似以下内容：

```
deployments "flask" with revision #2
Pod Template:
  Labels:  pod-template-hash=1082750864
  run=flask
  Annotations:  kubernetes.io/change-cause=deploying image 0.1.1
  Containers:
   flask:
    Image:  quay.io/kubernetes-for-developers/flask:0.1.1
    Port:  <none>
   Environment:  <none>
    Mounts:  <none>
  Volumes:  <none>
```

您可以看到我们刚刚创建的注释，以及我们更改的容器镜像版本。

# 回滚

部署资源包括回滚到先前版本的能力。最简单的形式是`kubectl rollout undo`命令。如果您想要回滚到先前镜像运行的 Pods，您可以使用以下命令：

```
kubectl rollout undo deployment/flask
```

这将逆转该过程，执行相同的步骤，只是回到先前的部署资源配置。

如果您有多个版本，您可以使用`--revision`选项回滚到特定版本。您还可以使用`rollout status`命令和`-w`选项观察过程更新。例如，如果您刚刚调用了`undo`命令，您可以使用以下命令观察进度：

```
kubectl rollout status deployment/flask -w
```

```
Waiting for rollout to finish: 0 of 1 updated replicas are available...
deployment "flask" successfully rolled out
```

即使您撤消或回滚到先前版本，部署历史记录仍会不断向前滚动版本号。如果您熟悉使用 Git 进行源代码控制，这与使用`git revert`命令非常相似。如果您在撤消后查看历史记录，您可能会看到以下内容：

```
kubectl rollout history deployment/flask
```

```
deployments "flask"
REVISION  CHANGE-CAUSE
2         <none>
3         <none>
```

# 使用 kubectl set 命令进行更新

更新容器镜像是一个非常常见的任务。您也可以直接使用`kubectl set`命令更新该值，就像我们之前提到的那样。如果部署资源已添加`change-cause`注释，那么使用`kubectl set`命令将在您进行更改时更新该注释。例如：

```
# delete the deployment entirely
kubectl delete deployment flask
deployment "flask" deleted
```

```
# create a new deployment with the run command
kubectl run flask --image=quay.io/kubernetes-for-developers/flask:latest
deployment "flask" created
```

```
# add the initial annotation for change-cause
kubectl annotate deployment/flask kubernetes.io/change-cause='initial deployment'
deployment "flask" annotated
```

```
# update the container version with kubectl set
kubectl set image deployment/flask flask=quay.io/kubernetes-for-developers/flask:0.1.1
deployment "flask" image updated
```

如果您现在查看历史记录，它将包括使用`set`命令进行的更改：

```
kubectl rollout history deployment/flask
```

```
deployments "flask"
REVISION  CHANGE-CAUSE
1         initial deployment
2         kubectl set image deployment/flask flask=quay.io/kubernetes-for-developers/flask:0.1.1
```

当您使用代码创建服务和部署时，您可能会发现使用这些命令快速创建部署并更新它们非常方便。

**注意**：避免在引用容器镜像时使用`latest`标签的另一个原因：更新部署需要更改部署规范。如果您只是在部署后面更新镜像，部署将永远不知道何时更新它。

到目前为止，我们描述的升级都是幂等的，并且期望您可以无缝地向前或向后更改容器。这期望您创建和部署的容器镜像是无状态的，并且不必管理现有的持久数据。这并不总是如此，Kubernetes 正在积极添加对处理这些更复杂需求的支持，这个功能称为 StatefulSets，我们将在未来的章节中进一步讨论。

# 总结

在本章中，我们首先回顾了一些关于如何开发代码以在容器中运行的实用注意事项。我们讨论了从程序中获取日志的选项，以及在代码运行时访问 Pods 的一些技术。然后，我们回顾了 Kubernetes 的标签和选择器的概念，展示了它们在我们迄今为止使用的命令中的用法，然后看了一下 Kubernetes 服务概念，以公开一组 Pods（例如在部署中）给彼此，或者对 Kubernetes 集群外部。最后，我们结束了本章，看了一下部署的推出，以及您如何推出更改，以及查看这些更改的历史记录。
